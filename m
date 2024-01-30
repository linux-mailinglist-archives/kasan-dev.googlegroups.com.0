Return-Path: <kasan-dev+bncBDV37XP3XYDRBDXJ4OWQMGQEZE65V3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id D067B8425C6
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jan 2024 14:07:27 +0100 (CET)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-214d020850esf2861904fac.2
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jan 2024 05:07:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706620046; cv=pass;
        d=google.com; s=arc-20160816;
        b=xyFhX31xXcwn9xmIs/SbX+a/zex5KUv683I3XtEhPEaj8tEsPLAtKucdwshWWS6gLJ
         g2WKAI1rriy/hxEGze2N1llxnwXZTM3qdB1FutYUHD7yKkfHDG6TQrqMw1iB++RNwjtr
         SYnpLtB+T7UY2tTSrYGxhN2tlaaa3Ii57OGP+rXRsskBqgIwtDXgllfvCKdx+rFrOoxJ
         u3efwregpZ8cg026vpe5HaModVk9cVAYWL/JLfQE/xPLhpO3mLDUj3g915Yp0DZY3m7w
         PaB0r3QkBsxPb6soavaiopdJlLRjQ8hOHdnG6rTnUsZ4G2KbLH2bnimP45AI72elbeJl
         gWcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=dUbL6qELgltFBZkhO3nralFbjRuCraIBWq3sh+8XMyE=;
        fh=xeCn5p7qRGCkWwGqNIxKhkXzb8rbqE1yupV31i+mXW8=;
        b=SiTG4Fhj581eF4viS9susW0ZsRDI/PnTtx+7rS1LUkFeB3mpUdV2JGuSHnJ5gQGSwm
         tgXfaGiIi67f/5SppdE3dP9BKaCSlj5cFN8d6QvyYtOBmUjLh6i8NKUhMQmuQMbwT6dE
         aFDpz+6PKSYTrUYzEbpCDrT6slqjDXLEGXCLRy+wvUrN4Tuh2BO1C0w2H2nn54UtQUYV
         Q7H5eUyKvbxnmTD3c8WGuOWkF7wph0nVF3Bb8jYJGVByBNBTZD2iT8CSTa1OeZOhbnMP
         XWVXPfdITtz/kHwvXstbhIl8IyQR6DICbIEpxQtiIP4Ffqg2dYAYgwoipWsWqoFYkhnq
         9zHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706620046; x=1707224846; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dUbL6qELgltFBZkhO3nralFbjRuCraIBWq3sh+8XMyE=;
        b=ss7RxesvX8xTKglx1Kg6t/q+5hleReE3E9tVQHTv8aJIeius6DTntyILWXfhXymkND
         aiyZ+lm/kphWjq8nQ6QNMFHbAYwWQeNVRLTaQHlM0uua91IMMNP2AfxsmINJsBuEZuQX
         iebf9vslrGa4+07/AamiEz7XhZlUtZb9xS7qjOgNXpivV15aGEDf42o3T6gihoBnsbe+
         7VaukmF/1Zq+B5MCXpHYGjQ21Y1YCKgIKcPIX6YrseLG471CB70ZsySrWLgzNZt1B2oa
         ILdayhb9/kREmjt478FXZoDoAVSpss+OhRtAKQk6vCVmAObVZdFTUsbtowIP3wcZXz3v
         zjhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706620046; x=1707224846;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dUbL6qELgltFBZkhO3nralFbjRuCraIBWq3sh+8XMyE=;
        b=JhAL+37EOknI1yaQVzLTVlR1qVa0T2g8Pwf4RhwmegLaibzQnERIVQcgHurswsp+lx
         JgZ5YhZyoJfVedtutOco7G81bAhfoq2Gfn/yTvHg8SNMkVMMZRBEaojLmssXznpCOHRg
         0dPot7fmYlV3MLlbPBv+N0R7beIcq8AAeOi81/aiYID7CDA41u4c/5kbA1r/tDw2hHUQ
         +9pp2upKyvy7LUZsMZAntbdG7Njjl7HewTwL6eLUyg7wb3BgjwBTemwRWK5OH27cSvaB
         itdDwJO0oCb7Gr0I88noNBwOjM8vh0kugiZyQb7ucs4WwSzuG7M3IIaWf/LFNSzbubjj
         FG1g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwwqrXo1CfMvdrih61Hln1Ecd58LMEKGgeiUYbk2xULvCUO/4q/
	X2hqvPAiGLzXPQoF+6bBaZo0KTMV/94cerTC4jfjYOwTiOEP9JVJ
X-Google-Smtp-Source: AGHT+IGL0Lle2sB+GXC2+wd6WDgNOGkb1UGzmMMqCI7wyxBEtTpmTzlsfq1WFHwrF8T18vKP8RVAWw==
X-Received: by 2002:a05:6870:d3c8:b0:218:5067:7108 with SMTP id l8-20020a056870d3c800b0021850677108mr8346364oag.19.1706620046554;
        Tue, 30 Jan 2024 05:07:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:158d:b0:218:b05a:1019 with SMTP id
 j13-20020a056870158d00b00218b05a1019ls349456oab.2.-pod-prod-02-us; Tue, 30
 Jan 2024 05:07:25 -0800 (PST)
X-Received: by 2002:a05:6808:1782:b0:3be:85d1:3ff2 with SMTP id bg2-20020a056808178200b003be85d13ff2mr2730406oib.40.1706620045719;
        Tue, 30 Jan 2024 05:07:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706620045; cv=none;
        d=google.com; s=arc-20160816;
        b=NvmvhSKLXkd28XvCOiMJ9vUt/DAg+xv7NCQt/OdbqKXSkqk1oMmfZczHCLkiNHN8MC
         fHivUyghiDMeerqtxyK1vLju2+kFVw/w9VGyEqc63mNREdvUr1EjOMOoLls+9dGJjaX4
         HeurSSYbSO32PcSwpy3rUkAL4Fmg3GEy0Q7YLdsgfTgttjtIPO+8mtPcK2DZszaGKORO
         V3/XjaE7Zd9bi0pdUM/RiuPIe2P+bCfewMcMNaSVz9lX/TVqO/PVSDC9IRMhOJWklMzv
         i/rb8/PV7NNeOtaZkvSzWtOzU0aTEzdUKF76s2VPX2dejMyPG6KVq5JPC8yQxJq5WRj9
         bl5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=/9gO6r1nlR9TClAdhf6DEhhtE3vltwVttojRzTatWgg=;
        fh=xeCn5p7qRGCkWwGqNIxKhkXzb8rbqE1yupV31i+mXW8=;
        b=sKwlotCmkvOfacetUtiPk8zMln+dPNkXUiujIPnsPYsUTKqaqorq5SbhiIu87cRhtZ
         6dIEX+IG7NOBA3CPnr/xmKpu9GK6aYJ80JgEYInNjGbeyPuHQMO/DogS+o1P/ap2Xwj/
         sZNeq5gs1JkccvyKVTkfOAuAyc4zOuIFpSNpHcQuwFEqcXTB5IUPvBc+1MklU+nUxA/j
         VBglNrPNg+0bVjl7+z3iN72bECnS1dtpJ17lRbPRz4qYCcp3JurBxctkFkRvIjI98/A4
         K4BZ7sghpF0Qk3gp79WP5+E801VPvsO8BRq2iqM+EqGl9ft3tOCFK3QWFO2K8ExnPzOL
         TuiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 13-20020a54418d000000b003be04bcac59si691680oiy.3.2024.01.30.05.07.25
        for <kasan-dev@googlegroups.com>;
        Tue, 30 Jan 2024 05:07:25 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 80839DA7;
	Tue, 30 Jan 2024 05:08:08 -0800 (PST)
Received: from FVFF77S0Q05N (unknown [10.57.48.92])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 9D8453F762;
	Tue, 30 Jan 2024 05:07:20 -0800 (PST)
Date: Tue, 30 Jan 2024 13:07:17 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Tong Tiangen <tongtiangen@huawei.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, James Morse <james.morse@arm.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	"Aneesh Kumar K.V" <aneesh.kumar@kernel.org>,
	"Naveen N. Rao" <naveen.n.rao@linux.ibm.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, wangkefeng.wang@huawei.com,
	Guohanjun <guohanjun@huawei.com>
Subject: Re: [PATCH v10 2/6] arm64: add support for machine check error safe
Message-ID: <Zbj0heg7eFukm_5Z@FVFF77S0Q05N>
References: <20240129134652.4004931-1-tongtiangen@huawei.com>
 <20240129134652.4004931-3-tongtiangen@huawei.com>
 <ZbflpQV7aVry0qPz@FVFF77S0Q05N>
 <eb78caf9-ac03-1030-4e32-b614e73c0f62@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <eb78caf9-ac03-1030-4e32-b614e73c0f62@huawei.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Jan 30, 2024 at 06:57:24PM +0800, Tong Tiangen wrote:
> =E5=9C=A8 2024/1/30 1:51, Mark Rutland =E5=86=99=E9=81=93:
> > On Mon, Jan 29, 2024 at 09:46:48PM +0800, Tong Tiangen wrote:

> > > diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> > > index 55f6455a8284..312932dc100b 100644
> > > --- a/arch/arm64/mm/fault.c
> > > +++ b/arch/arm64/mm/fault.c
> > > @@ -730,6 +730,31 @@ static int do_bad(unsigned long far, unsigned lo=
ng esr, struct pt_regs *regs)
> > >   	return 1; /* "fault" */
> > >   }
> > > +static bool arm64_do_kernel_sea(unsigned long addr, unsigned int esr=
,
> > > +				     struct pt_regs *regs, int sig, int code)
> > > +{
> > > +	if (!IS_ENABLED(CONFIG_ARCH_HAS_COPY_MC))
> > > +		return false;
> > > +
> > > +	if (user_mode(regs))
> > > +		return false;
> >=20
> > This function is called "arm64_do_kernel_sea"; surely the caller should=
 *never*
> > call this for a SEA taken from user mode?
>=20
> In do_sea(), the processing logic is as follows:
>   do_sea()
>   {
>     [...]
>     if (user_mode(regs) && apei_claim_sea(regs) =3D=3D 0) {
>        return 0;
>     }
>     [...]
>     //[1]
>     if (!arm64_do_kernel_sea()) {
>        arm64_notify_die();
>     }
>   }
>=20
> [1] user_mode() is still possible to go here,If user_mode() goes here,
>  it indicates that the impact caused by the memory error cannot be
>  processed correctly by apei_claim_sea().
>=20
>=20
> In this case, only arm64_notify_die() can be used, This also maintains
> the original logic of user_mode()'s processing.

My point is that either:

(a) The name means that this should *only* be called for SEAs from a kernel
    context, and the caller should be responsible for ensuring that.

(b) The name is misleading, and the 'kernel' part should be removed from th=
e
    name.

I prefer (a), and if you head down that route it's clear that you can get r=
id
of a bunch of redundant logic and remove the need for do_kernel_sea(), anyw=
ay,
e.g.

| static int do_sea(unsigned long far, unsigned long esr, struct pt_regs *r=
egs)
| {
|         const struct fault_info *inf =3D esr_to_fault_info(esr);
|         bool claimed =3D apei_claim_sea(regs) =3D=3D 0;
|         unsigned long siaddr;
|=20
|         if (claimed) {
|                 if (user_mode(regs)) {
|                         /* =20
|                          * APEI claimed this as a firmware-first notifica=
tion.
|                          * Some processing deferred to task_work before r=
et_to_user().
|                          */
|                         return 0;
|                 } else {
|                         /*
|                          * TODO: explain why this is correct.
|                          */
|                         if ((current->flags & PF_KTHREAD) &&
|                             fixup_exception_mc(regs))
|                                 return 0;
|                 }
|         }
|=20
|         if (esr & ESR_ELx_FnV) {
|                 siaddr =3D 0;
|         } else {
|                 /* =20
|                  * The architecture specifies that the tag bits of FAR_EL=
1 are
|                  * UNKNOWN for synchronous external aborts. Mask them out=
 now
|                  * so that userspace doesn't see them.
|                  */
|                 siaddr  =3D untagged_addr(far);
|         }  =20
|         arm64_notify_die(inf->name, regs, inf->sig, inf->code, siaddr, es=
r);
|=20
|         return 0;
| }

> > > +
> > > +	if (apei_claim_sea(regs) < 0)
> > > +		return false;
> > > +
> > > +	if (!fixup_exception_mc(regs))
> > > +		return false;
> > > +
> > > +	if (current->flags & PF_KTHREAD)
> > > +		return true;
> >=20
> > I think this needs a comment; why do we allow kthreads to go on, yet ki=
ll user
> > threads? What about helper threads (e.g. for io_uring)?
>=20
> If a memroy error occurs in the kernel thread, the problem is more
> serious than that of the user thread. As a result, related kernel
> functions, such as khugepaged, cannot run properly. kernel panic should
> be a better choice at this time.
>=20
> Therefore, the processing scope of this framework is limited to the user
> thread.

That's reasonable, but needs to be explained in a comment.

Also, as above, I think you haven't conisderd helper threads (e.g. io_uring=
),
which don't have PF_KTHREAD set but do have PF_USER_WORKER set. I suspect t=
hose
need the same treatment as kthreads.

> > > +	set_thread_esr(0, esr);
> >=20
> > Why do we set the ESR to 0?
>=20
> The purpose is to reuse the logic of arm64_notify_die() and set the
> following parameters before sending signals to users:
>   current->thread.fault_address =3D 0;
>   current->thread.fault_code =3D err;

Ok, but there's no need to open-code that.

As per my above example, please continue to use the existing call to
arm64_notify_die() rather than open-coding bits of it.

Mark.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Zbj0heg7eFukm_5Z%40FVFF77S0Q05N.
