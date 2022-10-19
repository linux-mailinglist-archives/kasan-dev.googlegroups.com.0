Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZHVYCNAMGQEI4ELABY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id A103A604F35
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 19:59:01 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id d4-20020a05683018e400b00661a05b6cf3sf8395968otf.6
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 10:59:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666202340; cv=pass;
        d=google.com; s=arc-20160816;
        b=scXH5djcH/SfC7+I6I4StoEuktkCM7F0EZ7jbwBFemgfhaeC3H8gBhtLFILvnxEUy+
         Bt3ymCzs2bPxEH4fEoZ33lpIGOQzTWMn4JWGGv/6qXEkiEG+VyTvO4DNZ7Ci3Hq/iomS
         NRhw1U/9hUYnrVwudKDBNW4yVOBal4wHrO6MGPIiJE+WM8sXdqbxC53P4DvpCYPRIVuE
         rJGuE/u1NBK7CcTTNAoNrnZNWLwt9k40dEzhYY4CwQXkmOKP/eXcKeQ6gL27btyUKNpS
         ezC/PU85mnOr1lys3+Wo8O/PMtO7MAxHyWtyeB6jSklpd4amMUsTn1Tg5offXgD3H8Wy
         macA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5Gsf+3KPD/gx+nkIIbriAjtMYqhRmLFxNx1Fhlpog/o=;
        b=QSBoAc/wDHKNfWJ/wq5ktBoX6LWhAsKyXGB4f3B7BR5QQsOjDtBAUzS0D6Wg5DC8vF
         WrBo8Fb6KZZ4QZjvoRJBQzLIUUHganc/q7ldsyPRGhAukipzPr+YMbNvMMJ6NJZ/sKAj
         oboIdRmojvdl3nfzALBmBbtnPjhEANyzKAFrSCXn14YUvsQ8bU7NzHEVwf9Zb/9EFt4U
         kXgVJiIaM0yS7UPmKHLPr/S+QmkGYSpYZ8ybCJLTJv99hifaWBn14T1kxyzr3FSCbvGw
         ++Nj0vRERcM88Va5m2lLoKAIRAc9b6uFP7sMBshDjULTJrPNfzitYnxH3xmi2mIJ5npW
         6n3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RfiBykGY;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5Gsf+3KPD/gx+nkIIbriAjtMYqhRmLFxNx1Fhlpog/o=;
        b=jWi+JBIPr1R9cz/9zg5UQz5oJQlFAHpIoaIYwWYW5Rxv2l1w+DW+VWZsvVy5aYYaHN
         miAypHMyouyu+P3wFl3NEIFvABC49z5Ir+SYAD95YYNobYgTRZ6A/AoEGsLfD9VvbFyn
         Y3BGW3V1BomgPa8LPhbkSGPpgbC5NrFwEVD9mQ1ivuDsMxTHuvQPUD25ftOJEfgMH7K/
         xzCDXeGxc40Dtb0TnO6So7W5NU58BGbmCphU9H16wRZUCukp3do4VvVkEzQ4uz+xdMFm
         ZCk3HUVB59fRi6tjL6oQG8FsQpeUCDO7jWXj4fdLncP6aR76MmzcMCk0FUIqpbMa3VX5
         UuEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5Gsf+3KPD/gx+nkIIbriAjtMYqhRmLFxNx1Fhlpog/o=;
        b=UyQtldMoTa0xtEWSvaLn7FtlKAOjRKsZjZIJs5w5FLGRw+icDyBPz2G3dIpEB5pDa8
         Qkxpq9hFMIperlgqs8HXtQOFmEF4bijnWWPpO5i1Lpc25XkDSa4J8zx281PATDRoDQj+
         M5ghFwRMylUz/6e070kkwp52duzwpFkcOWAK8wNHLFYvdLcsyFfdubpvOLFm3y1/v4Sg
         8DFWL1UxrqLJVOtf2gHd+OFgGa5+AB05y4eHEvpILkZeO3v+6iWbGi9bHd7FXKP4K/+v
         grtQB78lWDHIa+pWJkNlO/v8/p6nhVjOXOmtBbsAr7Jpm3oNgH9TrQejK5WkefMnkTPo
         +8FQ==
X-Gm-Message-State: ACrzQf1aA89u7PQIbnxp2kLohQ7aZZe0GoJTlKFrs6r2p/Tlhy4BhJm1
	u0NEwAtwGy1Eq2NKGHEQstM=
X-Google-Smtp-Source: AMsMyM4kzTGPDykLWjvX6ujmE0SSvwbOSTl7nzvd0Ze0VxdSCaRn27bKkUbpjYr0lDkjxBE4YbPXGw==
X-Received: by 2002:a05:6830:d85:b0:661:af2f:9a09 with SMTP id bv5-20020a0568300d8500b00661af2f9a09mr4611026otb.58.1666202340475;
        Wed, 19 Oct 2022 10:59:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:a584:b0:131:8180:91a with SMTP id
 c4-20020a056870a58400b001318180091als6089631oam.8.-pod-prod-gmail; Wed, 19
 Oct 2022 10:59:00 -0700 (PDT)
X-Received: by 2002:a05:6870:e40c:b0:132:8577:98da with SMTP id n12-20020a056870e40c00b00132857798damr23106140oag.205.1666202340064;
        Wed, 19 Oct 2022 10:59:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666202340; cv=none;
        d=google.com; s=arc-20160816;
        b=rb7pIt+tmainHACQnBl6vDzFBOId/T2KQpI6p5VDrDirm8WkaZPLCxXk+STdMDoQ1f
         Lv+oO8lgN9bpC7qOJkD0IfjsP+2IS/mBe2OIGkHNfnBjB/omuQ+ZnVgQqq19UdhIzMV2
         vvG+C2QtSu18m01wGF3uEUl5vOLEoxY02PF5iQqJGyDguv/VpzR1x4rD5PCUOehs5xjr
         IizytBdLer0RdeJRkR/zOILB/ZcriRnUl8KZTDaLmq3WwUKaBmBShvhk4jjuElBlqMoH
         58cUsDXc3fhv2DhxolKRrCfkzs0eHHpN3eHXaoSjqVFNyeO5sNiuO1hetuEQAV6udkP1
         oAvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=j5qHi6nHuKOfTP8VfwA/3L86+MJKtgh8T4LGj4c4RHw=;
        b=jXccAZzCMNwgl1w6nbGlUwe5UYIedGl30ntHsKdIindRPYaQL0GGgsv1bc+RD1nu1K
         cdzo63PWMrhz2jXPxfjT7lPTqzQpaHF2OhBVu4jW2HFAlCNwi2Yp0xXo3sbXUtxKrkQc
         1qMzdXl9/yndEO/4x8KNCD9uz4UmcwZEteO9UC9+rfqMHaE6ipcf2uQFgn6Mr+EFyhed
         AMYDH7V9yCItx/rdmeSmqUGxYYmxm2DPvg+YdGFutEXT79mgsVWmbjKjYbpjGm4KKxFL
         IZkAa8+OvmCfdZ8xkXcTb0RDS2xDejP8LUUaoRFfuouLveBhWlvmNXnHxtACsO0HWWGi
         61vQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RfiBykGY;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb29.google.com (mail-yb1-xb29.google.com. [2607:f8b0:4864:20::b29])
        by gmr-mx.google.com with ESMTPS id j75-20020acaeb4e000000b00353e4e7f335si770641oih.4.2022.10.19.10.59.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Oct 2022 10:59:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) client-ip=2607:f8b0:4864:20::b29;
Received: by mail-yb1-xb29.google.com with SMTP id 203so21756715ybc.10
        for <kasan-dev@googlegroups.com>; Wed, 19 Oct 2022 10:59:00 -0700 (PDT)
X-Received: by 2002:a05:6902:305:b0:6c3:b4d6:7a04 with SMTP id
 b5-20020a056902030500b006c3b4d67a04mr7524830ybs.93.1666202339610; Wed, 19 Oct
 2022 10:58:59 -0700 (PDT)
MIME-Version: 1.0
References: <20220915150417.722975-19-glider@google.com> <20221019173620.10167-1-youling257@gmail.com>
 <CAOzgRda_CToTVicwxx86E7YcuhDTcayJR=iQtWQ3jECLLhHzcg@mail.gmail.com>
In-Reply-To: <CAOzgRda_CToTVicwxx86E7YcuhDTcayJR=iQtWQ3jECLLhHzcg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 19 Oct 2022 10:58:23 -0700
Message-ID: <CANpmjNMPKokoJVFr9==-0-+O1ypXmaZnQT3hs4Ys0Y4+o86OVA@mail.gmail.com>
Subject: Re: [PATCH v7 18/43] instrumented.h: add KMSAN support
To: youling 257 <youling257@gmail.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Biggers <ebiggers@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=RfiBykGY;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as
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

On Wed, 19 Oct 2022 at 10:37, youling 257 <youling257@gmail.com> wrote:
>
>
>
> ---------- Forwarded message ---------
> =E5=8F=91=E4=BB=B6=E4=BA=BA=EF=BC=9A youling257 <youling257@gmail.com>
> Date: 2022=E5=B9=B410=E6=9C=8820=E6=97=A5=E5=91=A8=E5=9B=9B =E4=B8=8A=E5=
=8D=881:36
> Subject: Re: [PATCH v7 18/43] instrumented.h: add KMSAN support
> To: <glider@google.com>
> Cc: <youling257@gmail.com>
>
>
> i using linux kernel 6.1rc1 on android, i use gcc12 build kernel 6.1 for =
android, CONFIG_KMSAN is not set.
> "instrumented.h: add KMSAN support" cause android bluetooth high CPU usag=
e.
> git bisect linux kernel 6.1rc1, "instrumented.h: add KMSAN support" is a =
bad commit for my android.
>
> this is my kernel 6.1,  revert include/linux/instrumented.h fix high cpu =
usage problem.
> https://github.com/youling257/android-mainline/commits/6.1

What arch?
If x86, can you try to revert only the change to
instrument_get_user()? (I wonder if the u64 conversion is causing
issues.)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNMPKokoJVFr9%3D%3D-0-%2BO1ypXmaZnQT3hs4Ys0Y4%2Bo86OVA%40mai=
l.gmail.com.
