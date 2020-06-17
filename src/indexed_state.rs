#[cfg(test)]
struct St<F>(F);

#[cfg(test)]
impl<S1, S2, T, F, E> StateTR<S1> for St<F>
where
    F: FnOnce(S1) -> Result<(S2, T), E>,
{
    type Output = T;
    type Next = S2;
    type Error = E;

    fn run(self, state: S1) -> Result<(S2, T), E> {
        self.0(state)
    }
}

#[cfg(test)]
fn st<F>(f: F) -> St<F> {
    St(f)
}

#[allow(clippy::type_complexity)] // generic boxed function for a 'complex' signature
pub struct BoxStR<'state, S1, S2, T, E>(Box<dyn FnOnce(S1) -> Result<(S2, T), E> + 'state>);

pub fn boxed_state<'state, S1, S2, T, E, F>(f: F) -> BoxStR<'state, S1, S2, T, E>
where
    F: FnOnce(S1) -> Result<(S2, T), E> + 'state,
{
    BoxStR(Box::new(f))
}

impl<'state, S1, S2, T, E> StateTR<S1> for BoxStR<'state, S1, S2, T, E> {
    type Output = T;
    type Next = S2;
    type Error = E;

    fn run(self, state: S1) -> Result<(S2, T), E> {
        (self.0)(state)
    }
}

/// This is "just" the indexed state transformer applied to a Result monad.
/// This would be a lot simpler with HKTs, allowing us to decouple the indexed
/// state, output, and result computation, but you can't always get what you
/// need ...
pub trait StateTR<S> {
    // Required members
    type Output;
    type Next;
    type Error;

    fn run(self, state: S) -> Result<(Self::Next, Self::Output), Self::Error>;

    // Provided members : the below is just meant to gain conviction this type
    // is expressive enough
    fn map<F>(self, f: F) -> StateMapped<Self, F>
    where
        Self: Sized,
    {
        StateMapped(self, f)
    }

    fn and_then<Y, F>(self, f: F) -> StateBind<Self, F>
    where
        Y: StateTR<Self::Next, Error = Self::Error>,
        F: FnOnce(Self::Output) -> Y,
        Self: Sized,
    {
        StateBind(self, f)
    }

    // Shortcut for StateApplied<StateMapped<Self, FnOnce(T) -> (FnOnce(U) -> U)>, U> ..
    fn join<U>(self, other: U) -> StateJoined<Self, U>
    where
        U: StateTR<Self::Next, Error = Self::Error>,
        Self: Sized,
    {
        StateJoined(self, other)
    }

    fn get(self) -> StateGet<Self>
    where
        Self: Sized,
        Self::Next: Clone,
    {
        StateGet(self)
    }

    fn put(self, state: Self::Next) -> StatePut<Self, Self::Next>
    where
        Self: Sized,
    {
        StatePut(self, state)
    }
}

pub struct StateMapped<M, F>(M, F);
impl<S1, T, M, Y, F> StateTR<S1> for StateMapped<M, F>
where
    M: StateTR<S1, Output = T>,
    F: FnOnce(T) -> Y,
{
    type Output = Y;
    type Next = M::Next;
    type Error = M::Error;

    fn run(self, state: S1) -> Result<(Self::Next, Self::Output), Self::Error> {
        let StateMapped(m, f) = self;
        m.run(state).map(|(s2, t)| (s2, f(t)))
    }
}

pub struct StateBind<M, F>(M, F);
impl<S, T, M, F, X> StateTR<S> for StateBind<M, F>
where
    M: StateTR<S, Output = T>,
    F: FnOnce(T) -> X,
    X: StateTR<M::Next, Error = M::Error>,
{
    type Output = X::Output;
    type Next = X::Next;
    type Error = X::Error;

    fn run(self, state: S) -> Result<(Self::Next, Self::Output), Self::Error> {
        let StateBind(m, f) = self;
        m.run(state).and_then(|(s2, a)| f(a).run(s2))
    }
}

pub struct StateJoined<M, U>(M, U);
impl<S, X, M> StateTR<S> for StateJoined<M, X>
where
    M: StateTR<S>,
    X: StateTR<M::Next, Error = M::Error>,
{
    type Output = X::Output;
    type Next = X::Next;
    type Error = X::Error;

    fn run(self, state: S) -> Result<(Self::Next, Self::Output), Self::Error> {
        let StateJoined(m, x) = self;
        m.run(state).and_then(|(s2, _)| x.run(s2))
    }
}

pub struct StateGet<M>(M);
impl<S, M> StateTR<S> for StateGet<M>
where
    M: StateTR<S>,
    M::Next: Clone,
{
    type Output = M::Next;
    type Next = M::Next;
    type Error = M::Error;

    fn run(self, state: S) -> Result<(Self::Next, Self::Output), Self::Error> {
        let StateGet(m) = self;
        m.run(state).map(|(s2, _)| (s2.clone(), s2))
    }
}

pub struct StatePut<M, S>(M, S);
impl<S1, S2, M> StateTR<S1> for StatePut<M, S2>
where
    M: StateTR<S1, Next = S2>,
{
    type Output = ();
    type Next = M::Next;
    type Error = M::Error;

    fn run(self, _state: S1) -> Result<(Self::Next, Self::Output), Self::Error> {
        let StatePut(_m, s2) = self;
        Ok((s2, ()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The robots cycles between three types of states: inactive, Initializing,
    // Active.
    #[derive(Debug, PartialEq, Eq)]
    struct Inactive {}
    #[derive(Debug, PartialEq, Eq)]
    struct Initializing {
        position: i32,
    }
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Active {
        position: i32,
        odometer: u32,
    }

    fn setup() -> (
        Inactive,
        impl StateTR<Inactive, Output = i32, Next = Active, Error = ()>,
    ) {
        // The operations of the robot, all faillable, try to change the State data
        // or the state type, or both. Some have an output as well.
        let activate = st(|_s: Inactive| Ok((Initializing { position: 0 }, ())));
        let position = |i: i32| st(move |_s: Initializing| Ok((Initializing { position: i }, ())));
        let start = st(move |s: Initializing| {
            if s.position >= 0 {
                Ok((
                    Active {
                        position: s.position,
                        odometer: 0,
                    },
                    s.position,
                ))
            } else {
                Err(())
            }
        });
        let displace_to = |d: i32| {
            st(move |s: Active| {
                Ok((
                    Active {
                        position: d,
                        odometer: s.odometer + (s.position - d).abs() as u32,
                    },
                    d,
                ))
            })
        };
        // end of setup

        let robot = Inactive {};

        let initial_program = activate
            .join(position(12))
            .join(start)
            .and_then(move |x| displace_to(x + 1))
            .and_then(move |x| displace_to(x - 5));
        (robot, initial_program)
    }

    #[test]
    fn indexed_state_join_and_then() {
        let (robot, initial_program) = setup();
        let shutdown = st(|s: Active| Ok((Inactive {}, s.odometer)));
        // end of setup

        let program = initial_program.join(shutdown);

        // robot traveled a distance of 6
        assert_eq!(program.run(robot).unwrap().1, 6);
    }

    #[test]
    fn indexed_state_get() {
        let (robot, initial_program) = setup();
        // end of setup

        let peek = initial_program.get();

        assert_eq!(
            peek.run(robot).unwrap().1,
            Active {
                position: 8,
                odometer: 6
            }
        );
    }

    #[test]
    fn test_indexed_state_put() {
        let (robot, initial_program) = setup();
        // end of setup

        let reset = initial_program
            .put(Active {
                position: 0,
                odometer: 0,
            })
            .get();

        assert_eq!(
            reset.run(robot).unwrap().1,
            Active {
                position: 0,
                odometer: 0
            }
        );
    }

    #[test]
    fn indexed_state_map() {
        let (robot, initial_program) = setup();
        // end of setup

        let expand = initial_program.map(move |x| x * 2);

        assert_eq!(
            expand.run(robot).unwrap(),
            (
                Active {
                    position: 8,
                    odometer: 6
                },
                16
            )
        );
    }
}
