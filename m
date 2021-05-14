Return-Path: <kasan-dev+bncBCGJZ5PL74JRBZF57KCAMGQEQDAGHMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C919380DB5
	for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 18:01:41 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id a13-20020ac2504d0000b02901cc23500e8esf6390169lfm.0
        for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 09:01:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621008100; cv=pass;
        d=google.com; s=arc-20160816;
        b=UMLD3VHhXd3Fvq39lceYuoKKz8C6WA+joneZWT/6CR5JLPqp6uzXSANcI8b87U/P1r
         TtA7QB5X8fiJWqfYmvMY0cSQG9edZqlpRX6GGBAb4XkVUQW4lqBTVEOwVkmBIQyjF9t+
         jKK5m+pI/E8zwnVw6LRBFT2zcyZMK21q7mVtt0551A7Kb82jcvSeBmWui4IlxF+JeIuU
         41ltioqVBqTmk11U1Y90jbvRyNlA9DU+pVwl6bi+OBhlJpx3FYsHy23WUa2ZmBT6N9LA
         GMMBVNfXOTHmB7LbPOti+tCAno8Vs2YXLbmokAp/Q48DTkTA+4VX9TLPjwdMutU/AbjD
         QPIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language
         :content-transfer-encoding:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=mdyzwcpHwNDXNDd+lXLMkPE/lNAcwjliYplA2qk/0i4=;
        b=H/HayVUvgOqHApopJfEBwhC4kDagwQoj3cBI1n+1PDecU2eMlTOioDit8Fai8pJlY9
         TfkFHlKcJ6BU81YMFGy+nG9Fka84aN9yWL49kYu3pG4CB3/bL1hXclEqEZEQNlElnFbg
         aTX12HiW8rRIZ+g/Q3YoHIFpqUxThR/RIEw9EiACcVXuDF8VhibVM7zWMFC7RP+TPY79
         hPlwlzDFEhimdESN/Z5EM3nAkTHKlbiEmXAgpJCYnuysbGyHCoxC5XLEAY0DA3/LNhKU
         P7i1jsGGx6cK2Z9QiP4okcDENQViu2herxtUAvsFil72A4FGKc3BL4fJDxx7ElzQEz3G
         u6Jg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@colorfullife-com.20150623.gappssmtp.com header.s=20150623 header.b=eVzIHkJd;
       spf=pass (google.com: domain of manfred@colorfullife.com designates 2a00:1450:4864:20::52a as permitted sender) smtp.mailfrom=manfred@colorfullife.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-transfer-encoding:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mdyzwcpHwNDXNDd+lXLMkPE/lNAcwjliYplA2qk/0i4=;
        b=iB08FcUub2mskXef3llqobDQdRzlo4MhwUVyok4hyc5SXRoI8UurRk1ozfoxfqbAv+
         8ycsBPhUmV/g+FHQhjPZx02OHEuFxcb8UHpt6oD3nb5nMZrCfUct26Zw5pwiNOlWZgBc
         zGI+lQ9Ep2wUF9kBvD3VWQoihyOm5N5XWRnVdUc0IkDMm2o2ioppA/G6SPZ5Z14OAANq
         xy4leiI1Yjz1uUpGbSPB9gjCFX65yHGMoWPjnjzmNJBt71PelBZB53fL0jK3ZC67xc/l
         EPRW2XMpSSW70F9iDSb8EkR0zgh0ag9tDoEm+icCzSyH03q6KZmIipJz90btHj1/CjBa
         WvnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-transfer-encoding
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mdyzwcpHwNDXNDd+lXLMkPE/lNAcwjliYplA2qk/0i4=;
        b=Wpx87i9rIMB9huCqcO7422Ht5N94a5WvdzbmdD6gpNOLQYgpwz9lDxrIPr8rQ7dePZ
         F3CReGJrSV5ws4UMUyeEIcdJhJhYy29H+Q9yikQsR7GAo4rOj1hQmUTplWXezhPr1K+X
         j4Bia4sAIlH8Zyd0xov1GXEyyMYvJNzS5AHjiJbGAaeJLuxGKt/HiOjvyVtXs34/+w16
         Z3PtNv2WajL6WFHMz50eOHQvhfb4e6WyOzAldwlgYWIuvAgmYF94RTGPVegn+/u9OLqF
         fEFCQ7g6TPtTjhjpLJttQbwj4Y1cIK05dbekVU3V5oHzbthbtHQnZ+Y6SfUe7r7dHsyd
         CqlA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530QFRL96qz9jIygaRuxnnB2B1/xiKT24QHeT1zFmhC2iuTCSYvK
	UcBz3VoI6RZ05E9ayvY5JzI=
X-Google-Smtp-Source: ABdhPJxfmtiLLbpzpku8X5JHG7JUpspmxiIaIZ+ogpQKhVnwB+TE5cAgNE5M0Vz3XIH4Wq+5mxC2pg==
X-Received: by 2002:a2e:9d8b:: with SMTP id c11mr36017737ljj.437.1621008100823;
        Fri, 14 May 2021 09:01:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5e2c:: with SMTP id o12ls6009392lfg.2.gmail; Fri, 14 May
 2021 09:01:39 -0700 (PDT)
X-Received: by 2002:a19:2483:: with SMTP id k125mr32519837lfk.331.1621008099665;
        Fri, 14 May 2021 09:01:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621008099; cv=none;
        d=google.com; s=arc-20160816;
        b=eGAtcqz7S50ywvTNHyCZyN8n9El1y4ZZonUxTBRAEjUC5DzoTWi94m5yKQDKYX9GRR
         ewotSr8FmkVa61JM3vfZFaKJkoBY7TY+Bx0b+PzqOSlle+vJgR/wpWtlXgUUHn1TpxaB
         XxdljegX5SKlNFcLieya+1bRR1eEz4dOFbW3Pgx9DDZvGuQOVFZZNw6OU6p8haBoKpP7
         WI7P9e2C17P4bTMGExARd8hArCzoE1DBIPy4Q7BFpLPJr3awSMolUNc0JYN45R37Axkh
         1gJcTpXRTLXTk4TFpHxFloT18FRdFczP6r3lgt6tjKDwbV6W6KgyJMaBMr9sKEY/FnvW
         y6Ng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=yd0YOMLaUjGlgNJJGRY7ogVwKE514n0EDrTvayvp4V0=;
        b=A/MxF1L7pOrnjCqStkGUX+hRU+d9EYOrCWT/vmMBnWRjPn6NGDzdgnOfqc673IRqTh
         IlfJpqq2OaiimjBFRTnugMsbFsbi7z/m7urfo/CMMTiLJBEniF4dryzuFfx4S7Zvwn0k
         JVLM0Tjofjh+FUzSd8wAYB02q3O8y/s3v7007WlK6XjeMQolxpBSVIuhPN2saYFSja22
         LppYVmq5TL/nGKQVo+P2x68GvD74ohlRz+O5YhzxGQ79CrVe1+PAhuySf7k/dGEteeUi
         I+Ztz3+a3hVI83oNcb3E6YYu7V0Lyq11dK/du18NkiVPbUJuAUCDVYE7WfkILCu7nKx2
         iB9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@colorfullife-com.20150623.gappssmtp.com header.s=20150623 header.b=eVzIHkJd;
       spf=pass (google.com: domain of manfred@colorfullife.com designates 2a00:1450:4864:20::52a as permitted sender) smtp.mailfrom=manfred@colorfullife.com
Received: from mail-ed1-x52a.google.com (mail-ed1-x52a.google.com. [2a00:1450:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id k131si228974lfk.12.2021.05.14.09.01.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 May 2021 09:01:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of manfred@colorfullife.com designates 2a00:1450:4864:20::52a as permitted sender) client-ip=2a00:1450:4864:20::52a;
Received: by mail-ed1-x52a.google.com with SMTP id h16so874336edr.6
        for <kasan-dev@googlegroups.com>; Fri, 14 May 2021 09:01:39 -0700 (PDT)
X-Received: by 2002:a05:6402:1d8e:: with SMTP id dk14mr52012099edb.385.1621008099008;
        Fri, 14 May 2021 09:01:39 -0700 (PDT)
Received: from localhost.localdomain (p200300d9970469005bb43495a574ac97.dip0.t-ipconnect.de. [2003:d9:9704:6900:5bb4:3495:a574:ac97])
        by smtp.googlemail.com with ESMTPSA id h23sm3795056ejx.90.2021.05.14.09.01.38
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 May 2021 09:01:38 -0700 (PDT)
Subject: Re: ipc/sem, ipc/msg, ipc/mqueue.c kcsan questions
To: paulmck@kernel.org
Cc: kasan-dev <kasan-dev@googlegroups.com>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 Davidlohr Bueso <dbueso@suse.de>, 1vier1@web.de
References: <a9b36c77-dc42-4ab2-9740-f27b191dd403@colorfullife.com>
 <20210512201743.GW975577@paulmck-ThinkPad-P17-Gen-1>
 <343390da-2307-442e-8073-d1e779c85eeb@colorfullife.com>
 <20210513190201.GE975577@paulmck-ThinkPad-P17-Gen-1>
 <20210513220127.GA3511242@paulmck-ThinkPad-P17-Gen-1>
From: Manfred Spraul <manfred@colorfullife.com>
Message-ID: <8479a455-1813-fcee-a6ca-9fd0c2c6aabe@colorfullife.com>
Date: Fri, 14 May 2021 18:01:37 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.10.1
MIME-Version: 1.0
In-Reply-To: <20210513220127.GA3511242@paulmck-ThinkPad-P17-Gen-1>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
X-Original-Sender: manfred@colorfullife.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@colorfullife-com.20150623.gappssmtp.com header.s=20150623
 header.b=eVzIHkJd;       spf=pass (google.com: domain of manfred@colorfullife.com
 designates 2a00:1450:4864:20::52a as permitted sender) smtp.mailfrom=manfred@colorfullife.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Hi Paul,

On 5/14/21 12:01 AM, Paul E. McKenney wrote:
> On Thu, May 13, 2021 at 12:02:01PM -0700, Paul E. McKenney wrote:
>> On Thu, May 13, 2021 at 08:10:51AM +0200, Manfred Spraul wrote:
>>> Hi Paul,
>>>
>>> On 5/12/21 10:17 PM, Paul E. McKenney wrote:
>>>> On Wed, May 12, 2021 at 09:58:18PM +0200, Manfred Spraul wrote:
>>>>> [...]
>>>>> sma->use_global_lock is evaluated in sem_lock() twice:
>>>>>
>>>>>>   =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /*
>>>>>>   =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * Initial check f=
or use_global_lock. Just an optimization,
>>>>>>   =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * no locking, no =
memory barrier.
>>>>>>   =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
>>>>>>   =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!sma->use_global_lo=
ck) {
>>>>> Both sides of the if-clause handle possible data races.
>>>>>
>>>>> Is
>>>>>
>>>>>   =C2=A0=C2=A0=C2=A0 if (!data_race(sma->use_global_lock)) {
>>>>>
>>>>> the correct thing to suppress the warning?
>>>> Most likely READ_ONCE() rather than data_race(), but please see
>>>> the end of this message.
>>> Based on the document, I would say data_race() is sufficient:
>>>
>>> I have replaced the code with "if (jiffies %2)", and it runs fine.
>> OK, but please note that "jiffies" is marked volatile, which prevents th=
e
>> compiler from fusing loads.  You just happen to be OK in this particular
>> case, as described below.  Use of the "jiffies_64" non-volatile synonym
>> for "jiffies" is better for this sort of checking.  But even so, just
>> because a particular version of a particular compiler refrains from
>> fusing loads in a particular situation does not mean that all future
>> versions of all future compilers will behave so nicely.
>>
>> Again, you are OK in this particular situation, as described below.
>>
>>> Thus I don't see which evil things a compiler could do, ... .
>> Fair enough, and your example is covered by the section "Reads Feeding
>> Into Error-Tolerant Heuristics".  The worst that the compiler can do is
>> to force an unnecessary acquisition of the global lock.
>>
>> This cannot cause incorrect execution, but could results in poor
>> scalability.  This could be a problem is load fusing were possible, that
>> is, if successes calls to this function were inlined and the compiler
>> just reused the value initially loaded.
>>
>> The reason that load fusing cannot happen in this case is that the
>> load is immediately followed by a lock acquisition, which implies a
>> barrier(), which prevents the compiler from fusing loads on opposite
>> sides of that barrier().
>>
>>> [...]
>>>
>>> Does tools/memory-model/Documentation/access-marking.txt, shown below,
>>>> help?
>>>>
>>> [...]
>>>> 	int foo;
>>>> 	DEFINE_RWLOCK(foo_rwlock);
>>>>
>>>> 	void update_foo(int newval)
>>>> 	{
>>>> 		write_lock(&foo_rwlock);
>>>> 		foo =3D newval;
>>>> 		do_something(newval);
>>>> 		write_unlock(&foo_rwlock);
>>>> 	}
>>>>
>>>> 	int read_foo(void)
>>>> 	{
>>>> 		int ret;
>>>>
>>>> 		read_lock(&foo_rwlock);
>>>> 		do_something_else();
>>>> 		ret =3D foo;
>>>> 		read_unlock(&foo_rwlock);
>>>> 		return ret;
>>>> 	}
>>>>
>>>> 	int read_foo_diagnostic(void)
>>>> 	{
>>>> 		return data_race(foo);
>>>> 	}
>>> The text didn't help, the example has helped:
>>>
>>> It was not clear to me if I have to use data_race() both on the read an=
d the
>>> write side, or only on one side.
>>>
>>> Based on this example: plain C may be paired with data_race(), there is=
 no
>>> need to mark both sides.
>> Actually, you just demonstrated that this example is quite misleading.
>> That data_race() works only because the read is for diagnostic
>> purposes.  I am queuing a commit with your Reported-by that makes
>> read_foo_diagnostic() just do a pr_info(), like this:
>>
>> 	void read_foo_diagnostic(void)
>> 	{
>> 		pr_info("Current value of foo: %d\n", data_race(foo));
>> 	}
>>
>> So thank you for that!
> And please see below for an example better illustrating your use case.
> Anything messed up or missing?
>
> 							Thanx, Paul
>
> ------------------------------------------------------------------------
>
> commit b4287410ee93109501defc4695ccc29144e8f3a3
> Author: Paul E. McKenney <paulmck@kernel.org>
> Date:   Thu May 13 14:54:58 2021 -0700
>
>      tools/memory-model: Add example for heuristic lockless reads
>     =20
>      This commit adds example code for heuristic lockless reads, based lo=
osely
>      on the sem_lock() and sem_unlock() functions.

I would refer to nf_conntrack_all_lock() instead of sem_lock():

nf_conntrack_all_lock() is far easier to read, and it contains the same=20
heuristics

>     =20
>      Reported-by: Manfred Spraul <manfred@colorfullife.com>
>      Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
>
> diff --git a/tools/memory-model/Documentation/access-marking.txt b/tools/=
memory-model/Documentation/access-marking.txt
> index 58bff2619876..e4a20ebf565d 100644
> --- a/tools/memory-model/Documentation/access-marking.txt
> +++ b/tools/memory-model/Documentation/access-marking.txt
> @@ -319,6 +319,98 @@ of the ASSERT_EXCLUSIVE_WRITER() is to allow KCSAN t=
o check for a buggy
>   concurrent lockless write.
>  =20
>  =20
> +Lock-Protected Writes With Heuristic Lockless Reads
> +---------------------------------------------------
> +
> +For another example, suppose that the code can normally make use of
> +a per-data-structure lock, but there are times when a global lock is
> +required.  These times are indicated via a global flag.  The code might
> +look as follows, and is based loosely on sem_lock() and sem_unlock():
> +
> +	bool global_flag;
> +	DEFINE_SPINLOCK(global_lock);
> +	struct foo {
> +		spinlock_t f_lock;
> +		int f_data;
> +	};
> +
> +	/* All foo structures are in the following array. */
> +	int nfoo;
> +	struct foo *foo_array;
> +
> +	void do_something_locked(struct foo *fp)
> +	{
> +		/* IMPORTANT: Heuristic plus spin_lock()! */
> +		if (!data_race(global_flag)) {
> +			spin_lock(&fp->f_lock);
> +			if (!smp_load_acquire(&global_flag)) {
> +				do_something(fp);
> +				spin_unlock(&fp->f_lock);
> +				return;
> +			}
> +			spin_unlock(&fp->f_lock);
> +		}
> +		spin_lock(&global_flag);
> +		/* Lock held, thus global flag cannot change. */
> +		if (!global_flag) {
> +			spin_lock(&fp->f_lock);
> +			spin_unlock(&global_flag);

spin_unlock(&global_lock), not &global_flag.

That was the main results from the discussions a few years ago:

Split global_lock and global_flag. Do not try to use=20
spin_is_locked(&global_lock). Just add a flag. The 4 bytes are well=20
invested.

> +		}
> +		do_something(fp);
> +		if (global_flag)
> +			spin_unlock(&global_flag);
&global_lock
> +		else
> +			spin_lock(&fp->f_lock);
> +	}
> +
> +	void begin_global(void)
> +	{
> +		int i;
> +
> +		spin_lock(&global_flag);
> +		WRITE_ONCE(global_flag, true);
> +		for (i =3D 0; i < nfoo; i++) {
> +			/* Wait for pre-existing local locks. */
> +			spin_lock(&fp->f_lock);
> +			spin_unlock(&fp->f_lock);
> +		}
> +		spin_unlock(&global_flag);
> +	}
> +
> +	void end_global(void)
> +	{
> +		spin_lock(&global_flag);
> +		smp_store_release(&global_flag, false);
> +		/* Pre-existing global lock acquisitions will recheck. */
> +		spin_unlock(&global_flag);
> +	}
> +
> +All code paths leading from the do_something_locked() function's first
> +read from global_flag acquire a lock, so endless load fusing cannot
> +happen.
> +
> +If the value read from global_flag is true, then global_flag is rechecke=
d
> +while holding global_lock, which prevents global_flag from changing.
> +If this recheck finds that global_flag is now false, the acquisition
> +of ->f_lock prior to the release of global_lock will result in any subse=
quent
> +begin_global() invocation waiting to acquire ->f_lock.
> +
> +On the other hand, if the value read from global_flag is false, then
> +global_flag, then rechecking under ->f_lock combined with synchronizatio=
n
> +with begin_global() guarantees than any erroneous read will cause the
> +do_something_locked() function's first do_something() invocation to happ=
en
> +before begin_global() returns.  The combination of the smp_load_acquire(=
)
> +in do_something_locked() and the smp_store_release() in end_global()
> +guarantees that either the do_something_locked() function's first
> +do_something() invocation happens after the call to end_global() or that
> +do_something_locked() acquires global_lock() and rechecks under the lock=
.
> +
> +For this to work, only those foo structures in foo_array[] may be
> +passed to do_something_locked().  The reason for this is that the
> +synchronization with begin_global() relies on momentarily locking each
> +and every foo structure.
> +
> +
>   Lockless Reads and Writes
>   -------------------------
>  =20


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/8479a455-1813-fcee-a6ca-9fd0c2c6aabe%40colorfullife.com.
