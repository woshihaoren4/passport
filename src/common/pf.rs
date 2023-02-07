/// Point-Free

pub trait PFOk<Err>{
    #[inline]
    fn ok(self)->Result<Self,Err> where Self: Sized{
        Ok(self)
    }
}

impl<Err,T> PFOk<Err> for T {}

pub trait PFErr<Ok>{
    #[inline]
    fn err(self)->Result<Ok,Self> where Self: Sized{
        Err(self)
    }
}

impl<Ok,T> PFErr<Ok> for T {}