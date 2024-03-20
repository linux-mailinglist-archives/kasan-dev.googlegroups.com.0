Return-Path: <kasan-dev+bncBCCMH5WKTMGRB5NC5OXQMGQE4SRSOBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 33AE7881176
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 13:07:19 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-3673c792f3esf23415745ab.2
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 05:07:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710936437; cv=pass;
        d=google.com; s=arc-20160816;
        b=z7qW+lj3KByiCQgBX8HrIkeUZFIQx8+y1gfMwaQttTJUAu1cS1wDSBz3pJilUc4dqa
         iyM5/4wuALJFWzf7yJiv2Kfz6okbDMDsXCUG4iRd0jVg8w0g1RRPm7dzbISD9NQKf0NN
         Ws0JFvgPxU21acKyr7NYid+jK3ghHhDuRev9eOQx6tFYlLL5VvGJEM6vlfVUtdkmXj2Y
         MJCxEzt5rrHyIw89CiowIMvecQRrSepoOCUkyOtSPLZyHXYs15AoeYTUswWoKdZJqftu
         gKn+3ouTdAn4S1oUpua3DzHxd21OSzYb1Y6Lyaweg/s0kIA1wZPpTfdt874gLfRJPc6m
         e2DA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wB+uV7x95tmzpx/PkT1nJ3/TZCrdhT3gApAbH5cg5uM=;
        fh=S5/x4zZ+7Qw5Si5EWkEbrUcaGfEzh/ev1XjyB9HmgO4=;
        b=0GrB6jrgCTimH1qNEjGTPeMRWtItgtJrBJtOtV2nU15xQilyFvUpvmmvxzt+rBZsDb
         L4uWfMIpK64XzZl4xtoCRUnIyhd4B+EZN5EwJ1dho/Pl6Kj6CcJGD9uHvXhUynfKwi1j
         Dx/Ejd5n5ThkUttQOmRm6T+CBhOxhx1oT7sNnkxqOA6zdtA7OBo+W+4ZyODnaBPq8okU
         u2gOO71d4RDNaRe093dh96aT507h39CTlYyVycdfc2rBSsTWF4CPwMCLD6MgyDBP9Z7v
         1VxjMrPwdfPn7Hcydg7CzJuytUXbE/HITrFSyloi8/R7RtzSkNZBSBRpXcUVjTPXGZcr
         XjkA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="shwY/77R";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710936437; x=1711541237; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wB+uV7x95tmzpx/PkT1nJ3/TZCrdhT3gApAbH5cg5uM=;
        b=sioiQ02yln7lGiffRPXT9D4MAFrfp4h2s6yIKwF3vD6tTi4p5/anI/xHimJbVPrW2m
         z4bTL1cfAcP47tVlZ8JpC4hEb9yVZvTErHa1h2nakDSoL8Q4I69xgHPSYZzHdocohvw1
         mL9teF5YsQDRyAvY1WS1v6Wr+zYJS0RYH8LfJkELx8HticlQVfK3MdhRRtjmQgsaqC8S
         7a7pIg7UpvZGR7OD2IF4gjWLWfDKxzsQW/+uQZWgeW003Oqu1dS8VuLK8/nD6Eqw+b5b
         JwqP4dDb0MsOP/ifp6kh7Tchi0QQeuEfkTA/xhBLrQdNs4gPFckYqptPWAgP5xe+cUBG
         6+Uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710936437; x=1711541237;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=wB+uV7x95tmzpx/PkT1nJ3/TZCrdhT3gApAbH5cg5uM=;
        b=lS4tIru9BUDXOek2HqhrVYAWPsk69e/hpPlsiiIMm5TN8HAq2zXOS+j7Wk/ljWaSIb
         aN4C1X33j6mZl2jYg3CatcyfY19wu2qlAMz3PAzFtGi+Iaq4KT+rsNCbHhy+N8Z0VBi3
         jdW0qJzdiayfAtO7345CZuASIQ0AFRtjqlzTsFxsYjwe2BY6mjCbkp2INwRwDfI98Tpa
         D0QurLD83fZaCgyQEvqNz9VHHWzb/UYLmiWF1nzLJRshfsK8FUfilz+ooPiNW9Cgqup3
         Iby9YU49rtInIcmfpQtdVOAlOhobX25ox4g9oLc59OPU4L5IxQHV+VXsWx9jMrWDm9Gm
         wOww==
X-Forwarded-Encrypted: i=2; AJvYcCW9OIvm3pUIVaiI4T7nPO0rVQcXa707O1H0NlsfhD5CwX52BajbRK/NUUstPoCsfFh9PkmikcUaNRYL1cBUGiVHLzt16npulg==
X-Gm-Message-State: AOJu0YyJqC+gu/u+UTJ6E3NvIPioiwQ7F50cC3KpypLFZ7k3jnPGI3wH
	gUjCusIXrIgFopl7bZbh8TOmg/HF+rs4meXubyGUzGY9t+FyXy4k
X-Google-Smtp-Source: AGHT+IE+oWp1xIlibwXJ1H66DRCKFjPrTw1sOZejS1tD1wg2fqlN1Su+QiBCJ/WS4jZyYTbMZV/ovw==
X-Received: by 2002:a92:ddc8:0:b0:366:c4df:64c9 with SMTP id d8-20020a92ddc8000000b00366c4df64c9mr8471419ilr.12.1710936437669;
        Wed, 20 Mar 2024 05:07:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c267:0:b0:368:4301:dab0 with SMTP id h7-20020a92c267000000b003684301dab0ls1367257ild.2.-pod-prod-05-us;
 Wed, 20 Mar 2024 05:07:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVXlkrHKJwk7xdIUtTWplKkrbUoeZJhwlwOfQHpGFKDJBJ0xHPC2rw+Zn38vIctfdm3sxFkViuw/yRxB0EmcYiXUHvsnoyRKfBSPA==
X-Received: by 2002:a6b:6b0c:0:b0:7cf:1dcc:ab7 with SMTP id g12-20020a6b6b0c000000b007cf1dcc0ab7mr1431395ioc.12.1710936436834;
        Wed, 20 Mar 2024 05:07:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710936436; cv=none;
        d=google.com; s=arc-20160816;
        b=TIGstbNeQ9KAs17hjCtxRTmPDYhgt7SnAv1QNgi/dl0eK5GXAJkkuU4vnB81gHicy8
         +tlDLA/ZQhzDzqEysb1LUkprVW7ztY+2oFHeWi3eCxWd2M5OYOqJYL7eF6clpwZ8ikWR
         UaCYa1nbkRfDb/T9d+M9pM4d2KzL6zTuHukh7BVz7pppVQDSdLon5gUCmw2ltTGlgSIX
         YKPs9F1snwN1iWOFviqGQr53Fa21wFO8xdmdwnqw3v8LW30xFHo89/Qbj2r0AqrjmEjF
         yNa765H9lOm8Jxpk36V6tttMtetFW1RIpOOJFMVNJoWNVsgwGPkSgs8+BZGqD6tVHIhj
         273A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=z7DDAmZLzRu6HgzyxGlka/nEAH/Bp9s7j8g062J1qR0=;
        fh=meSRVT8cmcNST/dH9c3G0oLDdybWOovSJod0/xZZ2Us=;
        b=rI0wfbMV4QSHsM39rhc7aeiI3z4yz/OhqyXv5I/OEVwPHJO1nx3yQDhes62aw04fTw
         uiavhVUcgPSw8mIT+S4Dv2WUFBcaIF35Era073l+/F/kkKO917VZDhYXpi7l5HLt1o1q
         /Q5cZ1qmTARshXqO6XcR6I+8mhdnPKmPK9Ku6b5OiUX+kwLmi8FZCw0cgdNsj3oi/+nt
         ZzsFwXm2egijzzmstNTPkN81l8pw6hHaweOCDLVQu/yCtNmrdc0iZmQbx7TVPXyQJssl
         /HDCEHHxtWhgUWJk1eou76m7X8Qx3z1lJGuNVz0/n+qvJ0CZQWlEQM5Kb4ng0WSymI20
         a2gA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="shwY/77R";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf31.google.com (mail-qv1-xf31.google.com. [2607:f8b0:4864:20::f31])
        by gmr-mx.google.com with ESMTPS id n17-20020a056638265100b004791bba666esi612932jat.6.2024.03.20.05.07.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Mar 2024 05:07:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) client-ip=2607:f8b0:4864:20::f31;
Received: by mail-qv1-xf31.google.com with SMTP id 6a1803df08f44-6962e6fbf60so18482396d6.1
        for <kasan-dev@googlegroups.com>; Wed, 20 Mar 2024 05:07:16 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUyIiw8PA87p8kY+0u7rOr/tUzn5A+A5EkUBWQVjE1YHyNhpF4F4k3w/3Afe/fFekld8FWJYPMopVwRBhRaGwh1fSk/HyQ4tbvfYg==
X-Received: by 2002:a05:6214:2b97:b0:691:64e9:9a4a with SMTP id
 kr23-20020a0562142b9700b0069164e99a4amr25165795qvb.53.1710936436027; Wed, 20
 Mar 2024 05:07:16 -0700 (PDT)
MIME-Version: 1.0
References: <20240319163656.2100766-1-glider@google.com> <20240319163656.2100766-3-glider@google.com>
 <f9a8a442-0ff2-4da9-af4d-3d0e2805c4a7@I-love.SAKURA.ne.jp>
 <CAG_fn=UAsTnuZb+p17X+_LN+wY7Anh3OzjHxMEw9Z-A=sJV0UQ@mail.gmail.com> <dce41a35-aa2a-4e34-944b-7a6879f07448@I-love.SAKURA.ne.jp>
In-Reply-To: <dce41a35-aa2a-4e34-944b-7a6879f07448@I-love.SAKURA.ne.jp>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Mar 2024 13:06:33 +0100
Message-ID: <CAG_fn=UuC=d+jJOor1qMYjP48=mhSf7y=s=gwj6APaFroGqQdA@mail.gmail.com>
Subject: Re: [PATCH v1 3/3] x86: call instrumentation hooks from copy_mc.c
To: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Cc: akpm@linux-foundation.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, tglx@linutronix.de, 
	x86@kernel.org, Linus Torvalds <torvalds@linux-foundation.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="shwY/77R";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Wed, Mar 20, 2024 at 11:40=E2=80=AFAM Tetsuo Handa
<penguin-kernel@i-love.sakura.ne.jp> wrote:
>
> On 2024/03/20 18:29, Alexander Potapenko wrote:
> > But for KASAN/KCSAN we can afford more aggressive checks.
> > First, if we postpone them after the actual memory accesses happen,
> > the kernel may panic on the invalid access without a decent error
> > report.
> > Second, even if in a particular case only `len-ret` bytes were copied,
> > the caller probably expected both `src` and `dst` to have `len`
> > addressable bytes.
> > Checking for the whole length in this case is more likely to detect a
> > real error than produce a false positive.
>
> KASAN/KCSAN care about whether the requested address range is accessible =
but
> do not care about whether the requested address range was actually access=
ed?

I am not exactly sure under which circumstances a copy_mc may fail,
but let's consider how copy_to_user() is handled.
In instrument_copy_to_user()
(https://elixir.bootlin.com/linux/latest/source/include/linux/instrumented.=
h#L110)
we check the whole ranges before the copy is performed.
Assume there is buggy code in the kernel that allocates N bytes for
some buffer and then copies N+1 bytes from that buffer to the
userspace.
If we are (un)lucky enough, the userspace code may be always
allocating the destination buffer in a way that prevents
copy_to_user() from copying more than N bytes.
Yet it is possible to provide a userspace buffer that is big enough to
trigger an OOB read in the kernel, and reporting this issue is usually
the right thing to do, even if it does not occur during testing.
Moreover, if dst can receive N+1 bytes, but the OOB read happens to
crash the kernel, we'll get a simple panic report instead of a KASAN
report, if we decide to perform the check after copying the data.

>
> By the way, we have the same problem for copy_page() and I was thinking a=
bout
> https://lkml.kernel.org/r/1a817eb5-7cd8-44d6-b409-b3bc3f377cb9@I-love.SAK=
URA.ne.jp .
> But given that instrument_memcpy_{before,after} are added,
> how do we want to use instrument_memcpy_{before,after} for copy_page() ?
> Should we rename assembly version of copy_page() so that we don't need to=
 use
> tricky wrapping like below?

I think renaming the assembly version and providing a `static inline
void copy_page()` in arch/x86/include/asm/page_64.h should be cleaner,
but it is up to x86 people to decide.
The patch below seems to work:

=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
diff --git a/arch/x86/include/asm/page_64.h b/arch/x86/include/asm/page_64.=
h
index cc6b8e087192e..70ee3da32397e 100644
--- a/arch/x86/include/asm/page_64.h
+++ b/arch/x86/include/asm/page_64.h
@@ -8,6 +8,7 @@
 #include <asm/cpufeatures.h>
 #include <asm/alternative.h>

+#include <linux/instrumented.h>
 #include <linux/kmsan-checks.h>

 /* duplicated to the one in bootmem.h */
@@ -58,7 +59,14 @@ static inline void clear_page(void *page)
                           : "cc", "memory", "rax", "rcx");
 }

-void copy_page(void *to, void *from);
+void copy_page_asm(void *to, void *from);
+
+static inline void copy_page(void *to, void *from)
+{
+       instrument_memcpy_before(to, from, PAGE_SIZE);
+       copy_page_asm(to, from);
+       instrument_memcpy_after(to, from, PAGE_SIZE, 0);
+}

 #ifdef CONFIG_X86_5LEVEL
 /*
diff --git a/arch/x86/lib/copy_page_64.S b/arch/x86/lib/copy_page_64.S
index d6ae793d08faf..e65b70406d48a 100644
--- a/arch/x86/lib/copy_page_64.S
+++ b/arch/x86/lib/copy_page_64.S
@@ -13,13 +13,13 @@
  * prefetch distance based on SMP/UP.
  */
        ALIGN
-SYM_FUNC_START(copy_page)
+SYM_FUNC_START(copy_page_asm)
        ALTERNATIVE "jmp copy_page_regs", "", X86_FEATURE_REP_GOOD
        movl    $4096/8, %ecx
        rep     movsq
        RET
-SYM_FUNC_END(copy_page)
-EXPORT_SYMBOL(copy_page)
+SYM_FUNC_END(copy_page_asm)
+EXPORT_SYMBOL(copy_page_asm)

 SYM_FUNC_START_LOCAL(copy_page_regs)
        subq    $2*8,   %rsp

=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUuC%3Dd%2BjJOor1qMYjP48%3DmhSf7y%3Ds%3Dgwj6APaFroGqQdA%4=
0mail.gmail.com.
