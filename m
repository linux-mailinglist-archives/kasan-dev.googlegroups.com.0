Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQGH335AKGQEGSERQTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id C3302261386
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Sep 2020 17:31:12 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id j4sf3778491ljo.1
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 08:31:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599579072; cv=pass;
        d=google.com; s=arc-20160816;
        b=M1AxsDsjT0runxQjHdSr7gIPP8ZD56cnoTI/F+epth++5GOPeKxCZBiXb0iRAOgHRf
         85l9/q9bagREMCFyQXBNCbNDO9QtJJx4osyBNg5kOoEQ1O+avn1fjs/AFr0sdDqJMdff
         fkYOwB1q/o/0MEy9EOpJigSMuTRWNZSUDQDByx4K0lM2FXQM/4TLAdQrEkadEyJn9q53
         Oksq3+7jAuszxFkohFXtcdi7zLGOk35T8k2JUL2qe1HRoCE4fR+hKj+TcJC95Ns1Ptcv
         xOy7nDaEi8PhGhM5uf1Yx/u+ZFHan9U0hGnv/4E62nT4jvqdPyZ10fkiPKvirAVYRCVV
         pghA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=bmaO5p2IrL7fI7icstQpQZlJEgFgh/Di6ex74r2GH1E=;
        b=0OfK5vQ609cmnDxXURT98A1NfKB+Q+JYdMuEugknvJG90wgWunWYpQ/iXlcum/Rofx
         o4NvTqgDy+PbKp/8fwx474Z9DbRIjRg5PZ6Eikd4vrp9N1bN8oqtrpOzzM3VR5gzasx4
         p08doT35VK4sKrMhhEuSciEKM763tw0BZQnVM9IAlVRaVqwVwYToFaCLVtL65i5JFSZV
         Yfub2EDXDh0WorXodIzvxUBuR+SoUCSezfgDfw6371snEFEAFnSY0pZTeCYJjFG8nPxG
         INC0VOw13yugjykyhaq9uK/v1zcvAH3scN7CfEjWUHUTHDpWOqIWDYE3IgS2hIiEKWaa
         sTSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ve3aQ+oi;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=bmaO5p2IrL7fI7icstQpQZlJEgFgh/Di6ex74r2GH1E=;
        b=EIS17T6I0GPGJiQ5+T7cjbwWBFBvImWiMYYrvsG566hqms12qZRKs9pDrTJWVeQz+t
         +glyeCCtz9/IYFN3tQDQNmBigpzh2vRBW0cdH0S+ineshhWySNLF/PNkisWsi8HtMayb
         h8hcVSNNmvP2KDSfgTNvu3eJfitcYJ4HfDbwqMWroxLU7loIUpiHjRV5KL2uFBZpQp9/
         sbbwIcLWDvajN/Nq+lfwdjx8vPnCg+QJfNAZ+ZmajXnKBdsJioUJDs9hZeKh9pa+bHDz
         u/ZJMckSGJkKD7AA6m7YwBg+ArLGDelwgUTy3rUCG9DdnG/CHdwmKYr0mPO+aoxj9HV/
         7niA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bmaO5p2IrL7fI7icstQpQZlJEgFgh/Di6ex74r2GH1E=;
        b=osSZN/ir9adP2Wk30LHMtIF+aC3LkT04TpBvZtCqbLU4XKQTWc9gG48dMY1yhGq4dH
         yF+DHnoR07/F+bhGWMMduXHBXGpahw3uYToPVrKbSLqxp5PjT0HdNbUOtsbKkXrfV/il
         xUjaIAv1KR/puNjsANJa3DeHFsG+yD6V5jf9z2rWSl/Klp3WFdZwi4VxaOU26YGZNs1W
         2KUSRU2E1z6uF/TYN5hFEteERcaygqdHJUM06VHX8c8N4hF24VTspC8Xl8096CcWjDxS
         7ZeB9+1eiNnGU1HDpN3/dxNsV7GTP2UIcch25QQZSySiGIOl+ylONecMQ8QsBN1wbbfd
         ak8Q==
X-Gm-Message-State: AOAM531HEobVbtd0TftGTdn9iMWSNoSMadZf8JAT7Yd6XWqhJqr3q4c1
	26MMOqoHa72bUILT73Ns3CU=
X-Google-Smtp-Source: ABdhPJyRk4FYo6vt1Ht9OV3RHYSGyoqq2EZefwNVE+4OXq9DdtHgi8g3jdWBLpsxe1KF/omJOgrCXQ==
X-Received: by 2002:a2e:810e:: with SMTP id d14mr14037782ljg.100.1599579072330;
        Tue, 08 Sep 2020 08:31:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:544e:: with SMTP id d14ls2326696lfn.2.gmail; Tue, 08 Sep
 2020 08:31:11 -0700 (PDT)
X-Received: by 2002:ac2:53a3:: with SMTP id j3mr12861346lfh.86.1599579071064;
        Tue, 08 Sep 2020 08:31:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599579071; cv=none;
        d=google.com; s=arc-20160816;
        b=vtnsalfMaPL75Xe1u0DUKq9TArOgvUoy+x/+PTH3QN+3yWOB4aOc+AHAMXSscZvH62
         9KGwTOhBF2JSo6fTul4lYM4QPdZs1hnY/yTpCZXmh7pImGTV5EpnlIUiN4bL5W+YAGGk
         x9Fy+IXkjorG0vCwYCLfGsGognto/z+VBrvEiIGubaxM0XtBPQuYC3G9g/vqV/s75H5i
         UJShLXvxcN7z+qlE3GCJ9/RdMe/jKqRB6RY+FpWF7Od+Oute/u4Ea1cOPfQu7qQPopAy
         Qd8nsSst2f8GlrqEplJ0TeDBCWfXGnN0t+EUmu41WavVx2zAnHnecABzVVHI1DvgYB+l
         4dOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=YQgUsxZ9GX3vVBI6rWEDHgnkdvr/rXnkrQPmjYVedKg=;
        b=TVjiP0E/CI02jd2K4bXJRBq4/7P3dAIjrkX/ZMh+Ae5catk2buw+5Vbb13aCqrRM14
         TYNdKO3/uOQvrwK6Wf5e6I8GAZlnVZde8laxzWthzuXsmfaezI3RWaMDiQs3tjINXWjW
         /jHZ1c9LT06B87pWOk4tWwQws+Hb+ookmd+R8CIj6qRRul2qZgSbrCXzaM7mjmNwoAsL
         8ngp5gvLi0u7JHb6XPMe653Di6etVXCgHTyf7WI+t4r1H4gwzdBjAaVkGPpUk98rsTWn
         R4A0hwlXVHL7ueaaP7AnsNlBPw/X5dBsXb8QOtedbyAUTBslZDnfjZlmaJqKkHXSypan
         8/rg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ve3aQ+oi;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id y17si240224lfg.2.2020.09.08.08.31.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Sep 2020 08:31:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id c18so19553770wrm.9
        for <kasan-dev@googlegroups.com>; Tue, 08 Sep 2020 08:31:11 -0700 (PDT)
X-Received: by 2002:a5d:52c6:: with SMTP id r6mr172681wrv.141.1599579070236;
        Tue, 08 Sep 2020 08:31:10 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id d6sm34017392wrq.67.2020.09.08.08.31.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Sep 2020 08:31:09 -0700 (PDT)
Date: Tue, 8 Sep 2020 17:31:02 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dave Hansen <dave.hansen@intel.com>
Cc: glider@google.com, akpm@linux-foundation.org, catalin.marinas@arm.com,
	cl@linux.com, rientjes@google.com, iamjoonsoo.kim@lge.com,
	mark.rutland@arm.com, penberg@kernel.org, hpa@zytor.com,
	paulmck@kernel.org, andreyknvl@google.com, aryabinin@virtuozzo.com,
	luto@kernel.org, bp@alien8.de, dave.hansen@linux.intel.com,
	dvyukov@google.com, edumazet@google.com, gregkh@linuxfoundation.org,
	mingo@redhat.com, jannh@google.com, corbet@lwn.net,
	keescook@chromium.org, peterz@infradead.org, cai@lca.pw,
	tglx@linutronix.de, will@kernel.org, x86@kernel.org,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org
Subject: Re: [PATCH RFC 00/10] KFENCE: A low-overhead sampling-based memory
 safety error detector
Message-ID: <20200908153102.GB61807@elver.google.com>
References: <20200907134055.2878499-1-elver@google.com>
 <e399d8d5-03c2-3c13-2a43-3bb8e842c55a@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <e399d8d5-03c2-3c13-2a43-3bb8e842c55a@intel.com>
User-Agent: Mutt/1.14.4 (2020-06-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Ve3aQ+oi;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, Sep 08, 2020 at 07:52AM -0700, Dave Hansen wrote:
> On 9/7/20 6:40 AM, Marco Elver wrote:
> > KFENCE is designed to be enabled in production kernels, and has near
> > zero performance overhead. Compared to KASAN, KFENCE trades performance
> > for precision. 
> 
> Could you talk a little bit about where you expect folks to continue to
> use KASAN?  How would a developer or a tester choose which one to use?

We mention some of this in Documentation/dev-tools/kfence.rst:

	In the kernel, several tools exist to debug memory access errors, and in
	particular KASAN can detect all bug classes that KFENCE can detect. While KASAN
	is more precise, relying on compiler instrumentation, this comes at a
	performance cost. We want to highlight that KASAN and KFENCE are complementary,
	with different target environments. For instance, KASAN is the better
	debugging-aid, where a simple reproducer exists: due to the lower chance to
	detect the error, it would require more effort using KFENCE to debug.
	Deployments at scale, however, would benefit from using KFENCE to discover bugs
	due to code paths not exercised by test cases or fuzzers.

If you can afford to use KASAN, continue using KASAN. Usually this only
applies to test environments. If you have kernels for production use,
and cannot enable KASAN for the obvious cost reasons, you could consider
KFENCE.

I'll try to make this clearer, maybe summarizing what I said here in
Documentation as well.

> > KFENCE objects each reside on a dedicated page, at either the left or
> > right page boundaries. The pages to the left and right of the object
> > page are "guard pages", whose attributes are changed to a protected
> > state, and cause page faults on any attempted access to them. Such page
> > faults are then intercepted by KFENCE, which handles the fault
> > gracefully by reporting a memory access error.
> 
> How much memory overhead does this end up having?  I know it depends on
> the object size and so forth.  But, could you give some real-world
> examples of memory consumption?  Also, what's the worst case?  Say I
> have a ton of worst-case-sized (32b) slab objects.  Will I notice?

KFENCE objects are limited (default 255). If we exhaust KFENCE's memory
pool, no more KFENCE allocations will occur.
Documentation/dev-tools/kfence.rst gives a formula to calculate the
KFENCE pool size:

	The total memory dedicated to the KFENCE memory pool can be computed as::

	    ( #objects + 1 ) * 2 * PAGE_SIZE

	Using the default config, and assuming a page size of 4 KiB, results in
	dedicating 2 MiB to the KFENCE memory pool.

Does that clarify this point? Or anything else that could help clarify
this?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200908153102.GB61807%40elver.google.com.
