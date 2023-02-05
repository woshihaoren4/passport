/// Point-Free

pub trait PFOk<Err>{
    fn ok(self)->Result<Self,Err> where Self: Sized{
        Ok(self)
    }
}

impl<Err,T> PFOk<Err> for T {}

pub trait PFErr<Ok>{
    fn err(self)->Result<Ok,Self> where Self: Sized{
        Err(self)
    }
}

impl<Ok,T> PFErr<Ok> for T {}