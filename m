Return-Path: <kasan-dev+bncBC7OBJGL2MHBBF5B3CGAMGQESQGG6EI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 648C345571C
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 09:36:40 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id n4-20020acabd04000000b002a28d888c48sf4012470oif.9
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 00:36:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637224599; cv=pass;
        d=google.com; s=arc-20160816;
        b=V44nI88DAQi4QwmnmY17s5AdLSuQivyt5juxjuVhkaO7YdoFlsmA2MktyzQW+zKlho
         si5YI48mNMFtQHZ4TGQCqhOpAO/v5N5msL+uuhK3bsm28KiA3hyCGrkSpBMiDhGkz0at
         N3nrF25qYjJYyA8y/5QZEHY0tzSPuqWiAgNZY59gCpV/IO/KRTy6IEM4M1ZzQbYis7Pv
         fa1dCzPwfY5bb2U5sf5D+er+OraOXQPeYhkyW7Wfyj75TbLqTFPht/JQTesX4+qHPMBx
         1RpK4cqKCYIE5jSB4CKu3LNW8ETB3m9akxKGmcsSuhVOvws9p6qOYRCoisLjPPYIg/r6
         sN6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=cF7EdQoKNjltsv0SYYJcV+V3ErM7BJp005N7ouPWq3k=;
        b=lzpGyFFPnXDkPuRk31es9nHIZ596NIqVRIjVR5rl2PACY0/Gp+MZi5gJSTRihooe9I
         T1tolzFS/hC/8f2w+gemHCCX45KP2Idg0laR9SxBDXBSU5E8HTf2RLiRcI9M0ORjJtjY
         lo0vgf5G5SE3V78iEI+vDqfvIXoJfEfq6kNsEczWbihyJsMkpPjBlG8lkuUBa2+jkRD5
         6f9gcM19PwV+qiz17y6NXFdJHD0RK9oKoeF0opklhL9N58qggeh/W2W3mAOBqARUZi1Q
         q67y9MlmLLNthX+k6+ub9tn3qFjyZnIKRDwziLHe+49SWDqyuvs/Y5dB91q4/qX8eHC+
         tUvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ClnMjJ3y;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cF7EdQoKNjltsv0SYYJcV+V3ErM7BJp005N7ouPWq3k=;
        b=pi0/1O6ZAAP7QOdixnijpKajcKVLwcGQnvdVGjMlsivjHkb5LfoDyOleWfYGS8XEBY
         DSNTRtTlxRQEOpsqIiSPJjE4dXMmLZmO3mLwGk0T8XGugfTEN5YeDu0RBhyjmF2dTXo2
         gLzdqJMR3Bqw32R7IlOZfrehmCpQ2eSKRt/wflnrAFPRZFfYLUSH3i+l0lNtBZwF5OFX
         Inv2RQY6QmXhvH4+Ku4e32wFW/JNDSeKUtKsynI1/Fp9gmgUH/L4lnMRSxWGF52XzHZz
         a9Xp8epbwzWTfX/D9SzKK99dUd/OKyX0HI7G7QYw102D69QM+HKVpF0nfiWH8N27B7mW
         HCQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cF7EdQoKNjltsv0SYYJcV+V3ErM7BJp005N7ouPWq3k=;
        b=W3WoL+FsWRdmNnVzBCqqru4fDH3BHRaF7fiQcne95CSxfw0kOIwpFJq67WOF9+MS9w
         tigISuuGFgU8rbXjUUm4movepVpE2c0ONrhV5tA3yHX7jyUrlhwneOoI212FP/rvx7M5
         wQf1NPvzAEFgSXu9HB70RboEg9T4Aau/KiU6kflC60TMKEzWcXcT1RuuK64albHKc67/
         Qt5buSgCA4b5rDEnVmAI3IeQd0/ZV9aTH3dQEaZA3eiv5m/v940rUJ6oaiGAUAlPBmzn
         Z3NQG5vLBZSI0+LiQPXHp2c4y5L91w9LCL04XpG6rEZBPda5LOvS/aD+rYRodposoadf
         6BZg==
X-Gm-Message-State: AOAM533MSyO5BqdZjMI4JZPe1uwGsAHgrj4xalpJaoolYYobrBEmNqLt
	6YLCkKh1TgYjXquMMKUS/DE=
X-Google-Smtp-Source: ABdhPJz1XA6ZX8rzchnHDfywT1iXQotYjzimwVNLTI5lbwXssH/lGpKhA+YNNP+sqavyv3pxdzqLOA==
X-Received: by 2002:a54:4d89:: with SMTP id y9mr6112562oix.127.1637224599066;
        Thu, 18 Nov 2021 00:36:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:ad44:: with SMTP id w65ls1072250oie.5.gmail; Thu, 18 Nov
 2021 00:36:38 -0800 (PST)
X-Received: by 2002:a05:6808:1aa8:: with SMTP id bm40mr6040528oib.38.1637224598736;
        Thu, 18 Nov 2021 00:36:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637224598; cv=none;
        d=google.com; s=arc-20160816;
        b=b3zFxVVAklWdvW2+ilQThKm1m92Xtq81csl0U8XAcGc8jibmJfaMZuLL9ZF4S8vEH+
         9mtH+u5wQ2M83+gxGjRWr+m+E2qH0SKPX1e+c3tOsBPIfN/NakLFhCbeuO97YWFwWRIb
         TNH6dHwqWzd12xb3SF16C6Wg4tD4Kv+hICvEfKpoB3N1Jm4Z3YMtxybeD22PKKe1igV9
         HypmcxFOUB/PwNBu4lMhbJvKcLKF4u79/tWQFZcR+832gpBohnWnp1xrcncBoEpAd4sX
         +1gIAhmT3O+XHijeCrqahQmLDOtaEoy86ndKCnUaDcBPr/N2EQO9WysPot8orHCYv3ik
         BCXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NnqKcLxpSOIb1W6O4VXUNfxDfxrLxXy6WgJBvVpDNyg=;
        b=A94WAhmyq/6CVG/K8JSucEhEpYGUq5CzGdgwPa5TR3xZYB8h/g/wiLvH9GNYsFtDmP
         J9xK0yqZ65ocRncA+DzlywMQa+Or8AOeJaDr7Przz+UJ/V2KWBa30MMVx+aaMYXg/oYa
         UrwzVn2ELw8UR5dA81JxQxlN5FsKBxpnUBUDgu6gQtr07Qmv0uOLQpN1gAUIjG7dcmGc
         ZGqYH/TTILRx+p+fBB85uwEypwAPuzMwvbu1+wrdwO4yh/FOO8ENHlq6Elo/P2nHQGD9
         1k1sW/7vbvIbKYLJgVtF5MM+TTnyW+hpUKQcadxvRPcLsApCElntAVxWFa+X+WkjoIrW
         Kmrg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ClnMjJ3y;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22e.google.com (mail-oi1-x22e.google.com. [2607:f8b0:4864:20::22e])
        by gmr-mx.google.com with ESMTPS id d17si282476oiw.0.2021.11.18.00.36.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Nov 2021 00:36:38 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) client-ip=2607:f8b0:4864:20::22e;
Received: by mail-oi1-x22e.google.com with SMTP id q25so12853312oiw.0
        for <kasan-dev@googlegroups.com>; Thu, 18 Nov 2021 00:36:38 -0800 (PST)
X-Received: by 2002:a05:6808:118c:: with SMTP id j12mr6081616oil.65.1637224598305;
 Thu, 18 Nov 2021 00:36:38 -0800 (PST)
MIME-Version: 1.0
References: <a2ced905703ede4465f3945eb3ae4e615c02faf8.camel@gmail.com>
 <CANpmjNNSRVMO+PJWvpP=w+V6CR51Yd-r2ku_fVEvymae0g7JaQ@mail.gmail.com>
 <c2693ecb223eb634f4fa94101c4cb98999ef0032.camel@gmail.com>
 <YZPeRGpOTSgXjaE6@elver.google.com> <CAPDLWs88WLTPVnh1TtY3tOU6XLPucf8zKMhzCfxRv2HbCnKndA@mail.gmail.com>
 <CA+LMZ3r9ioqSN31w5v_Bkgs7UyPux=0MO8g0dQC16AxEiorBcg@mail.gmail.com>
 <CANpmjNMzv2b1srETOp1STjVWYZx-1XpdMm5yY485vSmd=wjJiw@mail.gmail.com>
 <CA+LMZ3qhJ1dnS3O9vKRA1DCF93Lpi-xq9PmStwhWC+ykRSGr_g@mail.gmail.com> <CAPDLWs9TR4gNHg+n2j2958yff+F6Ex0gVZxD8qtcPrgcYghfWA@mail.gmail.com>
In-Reply-To: <CAPDLWs9TR4gNHg+n2j2958yff+F6Ex0gVZxD8qtcPrgcYghfWA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 18 Nov 2021 09:36:26 +0100
Message-ID: <CANpmjNO5AQ_Yhk6k+N2u_sFPRP2JWRvkPqUSrS6koAYrqCx5-w@mail.gmail.com>
Subject: Re: KASAN isn't catching rd/wr underflow bugs on static global memory?
To: Kaiwan N Billimoria <kaiwan.billimoria@gmail.com>
Cc: Chi-Thanh Hoang <chithanh.hoang@gmail.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ClnMjJ3y;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as
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

On Thu, 18 Nov 2021 at 06:56, Kaiwan N Billimoria
<kaiwan.billimoria@gmail.com> wrote:
>
> On Thu, Nov 18, 2021 at 8:29 AM Chi-Thanh Hoang
> <chithanh.hoang@gmail.com> wrote:
> >
> > Thanks Marco for creating the bugzilla.
> > I will post my findings.

Thanks for adding your findings.

[...]
>
> Really interesting! Am trying to replicate along similar lines but it
> doesn't trigger !
>
> static char global_arr1[100];
> static int global_arr2[10];
> static char global_arr3[10];
> ...
> int global_mem_oob_left(int mode)
> {
>     volatile char w;
>     char *volatile array = global_arr3;
>     char *p = array - 3; // invalid, not within bounds
>
>     w = *(volatile char *)p;
>     ...
> }
>
> I also find that the global arrays seem to be laid out "in reverse",
> i.e., if i print their kernel va's:
> test_kmembugs:global_mem_oob_left(): global_arr1=ffffffffc07db8e0
> global_arr2=ffffffffc07db900 global_arr3=ffffffffc07db8c0
>
> And the last one, global_arr3, coincides with the BSS start:
>
> $ sudo cat /sys/module/test_kmembugs/sections/.bss
> 0xffffffffc07db8c0
>
> Can we infer anything here?

Infer why it's broken? Not really, there's no guaranteed order how
globals are laid out in memory. It's entirely up to the linker (except
if you explicitly put the symbol in some section).

The reason why GCC is not detecting this is because last I checked its
implementation of adding globals redzones is based on increasing
alignment of globals, which is really not the most reliable way to
ensure there's always padding. Clang explicitly adds data after a
global and doesn't rely on alignment.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO5AQ_Yhk6k%2BN2u_sFPRP2JWRvkPqUSrS6koAYrqCx5-w%40mail.gmail.com.
