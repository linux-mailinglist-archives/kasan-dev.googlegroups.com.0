Return-Path: <kasan-dev+bncBDW2JDUY5AORBNGZQ6UAMGQEE6NAKYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D5C479EFEF
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 19:09:10 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id 46e09a7af769-6bc4dfb93cbsf45884a34.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 10:09:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694624949; cv=pass;
        d=google.com; s=arc-20160816;
        b=A9BN4N9l6BcEm40hTRfSMtp1Qs6TnmQ/m0dfiOmMcP72I5Amjf2RxRTIYiQOqHwBLW
         75IbDAIpLilrsS+poFAYeYBaBFyBxR7z1AKC7BP8ElbPSghaHdlyByQMY9gwBnuhuohg
         viofmOkAcGL2BECF5af/Cf6w5krzNAvh4HaIRVIX7t+yzrkxR3X4nXbKghPiNU+DM+Dg
         +h6BeBPzMKxBdGeU5+HI/Sx30z4ZoNjuXrUNm+eBiaqjjWWENL66c/Oup2d7Po4tZ72X
         QmugjiyHmPCcHnGvjBnIwdVUWS2UMtRkssYrrmOMKkmyPeiy0iDkU5OzN5vzHvh028Ud
         x4mA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=k+dwB1eIAurvPgcIbIwCbCUy7uDHpIWHocEMkAGanrc=;
        fh=vhyMgzwtVf8Cd+Xluz+kIPeaZIksHpPCItLJmpWVnQM=;
        b=XMkD2FmW4uqnPXYK2oEtWtXbtcBBBfbZqUU8tt6xGgis9Kqd/aE54RU7MyuRpwC9/G
         54EGtYfPuxRPmhhtHeGH1PH/l0mIEgmRJp4MwnIJ/jWsQL//zmniyNxyuVLWI74Z1YZR
         dd6yV9JHErXkcYLCHqVchFL2/8IeX1L4IODpM40Piuye2qkRyPgFptg7FA+I6kPDBKNk
         HGOnMQRySXgxXFOJ49MEACRcc0Q6JlQMJXlsYhSOheTP4olqAJiw7UEwn2I+0kaPoCZV
         KdxQHL8xKk3ktSG+aky9Fm+2u9TZnurRb8jzFrt33S9/yXATZULoQuZxN/CI/aEugh/T
         ryQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=g3MWeIjw;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694624949; x=1695229749; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=k+dwB1eIAurvPgcIbIwCbCUy7uDHpIWHocEMkAGanrc=;
        b=mdIEI6M7B20JnnnH/HUiSQv2ZF+p0wxv5ly4SVOTnYxJTw0co6Ya80v3+Rh69YiR0w
         KiNumykitNzMT5WimFXBldayyLxP4sUSOLbhXkQotGPaw9fKBgebJg/ABhy5exMfz1zq
         G3ZD1JKY3KgU2qNribM2LMbrV7ToJqD3wKYUkzzR078dr9gkOZ4ahfV9OLDoTC8O0cbL
         zkoKkMm1IuEl20fUpu+8s9Q0h+ip5Z0WsnWoIHWcVbjvK1gSZ4TBZUWt+7eQLTy9eU0M
         lgosJfAkBt1JBrr0xJSeZufqnxHlnU7VFowAE4oFFunSnXuT4r+HeZQMgj2I2jRfZ9F0
         PpJQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1694624949; x=1695229749; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=k+dwB1eIAurvPgcIbIwCbCUy7uDHpIWHocEMkAGanrc=;
        b=PYLm9kTWjr05t16sstKKutSjSccwjyFKtx6az4PAklqsZJDaKvbvVve8nVCYn8tEYf
         foJEVqjhMvcTjBasHFO+HNnDLW/9P+5CxCbfnrKkc2djdoRHfPSbPnNRHjwBYoH2MZYw
         5NFvZZYA59++wDUAYgDN/aByH0az5pQVP6wqSgepNFx4q+4DjgQFskDn4U4Dbge+/bkM
         g9E1g1PmG+N7ureaRTAvuUyYS/408aQR9v2EQNkeWm6YVDdb19DpIcwRRYf54RX5KCpJ
         wZ2AGAsOJ7umuteR1QkAjINEGWKxhLb64ZPDwDWNrlDwJrW66v0KkenoNF9EbNVBbjlW
         3g9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694624949; x=1695229749;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=k+dwB1eIAurvPgcIbIwCbCUy7uDHpIWHocEMkAGanrc=;
        b=KH9EIh5YX8rdbF+6dqMwcvsXWX/NjVTShJRDOVodUbkPveMFlj9ALLGKzrQZLpCefy
         FC6AnT9p2t12C58spKLp52sqUiNrO91fYnD8uZU/LNdu67O+56YS97x/O0O3MIPs3Ade
         zKZIzvwWg3NBoCzKSr7rmPzgqzU93Ne4oE1ZV2g2BaDHYQXvt472Kr3B90t/Tc2s6zLF
         rTOPJK9cXk3ZiJhjKDi+D2k3O8qOMwX+32Bp53hfXV1+abto33s+Mth8S/M7Tyu19NtU
         LM1GH+SKPZvpecGUtDKmViLHU/5mvD069JR1Lwx8ozrwyVsAbWT9YAZGlgXbgGKuvL36
         nCyw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yyl10OdWsnImHhczMpxm6in1uKMmmeJ3Wg8df80Wq5rdMAjK2nh
	p4fg91ESq9Dgyrk6pdvhT8M=
X-Google-Smtp-Source: AGHT+IER/hwYS2v5LxciYeVWwUEo2k3TfhVCjDhE83ieF21AcNWMp0hIWrKO1aaW0Q+1zqOKZEnKJg==
X-Received: by 2002:a54:450a:0:b0:3a7:2693:3293 with SMTP id l10-20020a54450a000000b003a726933293mr3268239oil.16.1694624948792;
        Wed, 13 Sep 2023 10:09:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5202:0:b0:410:9efb:e3de with SMTP id r2-20020ac85202000000b004109efbe3dels674794qtn.2.-pod-prod-09-us;
 Wed, 13 Sep 2023 10:09:08 -0700 (PDT)
X-Received: by 2002:a05:620a:4511:b0:76c:b16b:ad74 with SMTP id t17-20020a05620a451100b0076cb16bad74mr3637329qkp.19.1694624947920;
        Wed, 13 Sep 2023 10:09:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694624947; cv=none;
        d=google.com; s=arc-20160816;
        b=TG+slB25b+LtyXZhyhBNSY+NZHhKmEaUHW0JVwdlO5FcDWC+IXdlLY87kHnuUoStbJ
         YIbuEDQtrGhCnEGPpQvbDhR4Ahz4XEAB/7zETdIvzxF5qAkXP8iyOGFb3n1Y7xBEt9dq
         G26++UN5FOTM+fjBLzetVIkEpcDVZ+u9z0kwxm9obbphtajD9fKPQdytbBcWrMfwuaAr
         YTSGGJJAUSL6cvk8cAsVbmALATPuULDs1geP/eR61fe5+4j6blgcIU85PlFvPVjPh9Y0
         cDmwl+LOAJL5JyyZjzb/Ea0HviGpHsa9273Y/bctTcot2YgqWNts37NtEiQCxdR8HVqL
         d7ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=wp3RFNUyA36WKs+LwiEbI6IPse2t1rgKYPkaJa9C0u8=;
        fh=vhyMgzwtVf8Cd+Xluz+kIPeaZIksHpPCItLJmpWVnQM=;
        b=BGIwTZinjRediACKswi+iccy4LgUZq0Ku+ERMyOckXjNTqUSbopK4god8p73ZH25cO
         ziH2rKJn3bno6EmFfXFHyzjiqbRAIEv8DsDkfmCYaKtEcW2QsDsQ7lOBYa54pTkIO0b6
         osrJT42NH8TMCqsU74ySklc2u3GTy7FmGB9m/4ONGSFJ18peIrk4T+/+cXjqLs8kja1W
         bR2/Z4r8a/ZGxS5b7KH2Xkh7z6JH+nILI0B+18lEwvNpQAkE/PNC0b+QHgJBDjMNwdxS
         rdMwJWUQvSlIBUOtcfPqggzNKx3QBniw4ERg+xZ852tJZG61s+2xUQ3w5ySQsUHezybq
         L2rg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=g3MWeIjw;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1031.google.com (mail-pj1-x1031.google.com. [2607:f8b0:4864:20::1031])
        by gmr-mx.google.com with ESMTPS id qz5-20020a05620a8c0500b0076daf89f666si1546232qkn.3.2023.09.13.10.09.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Sep 2023 10:09:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1031 as permitted sender) client-ip=2607:f8b0:4864:20::1031;
Received: by mail-pj1-x1031.google.com with SMTP id 98e67ed59e1d1-273fa877befso39210a91.2
        for <kasan-dev@googlegroups.com>; Wed, 13 Sep 2023 10:09:07 -0700 (PDT)
X-Received: by 2002:a17:90a:c584:b0:26d:d2d:1a90 with SMTP id
 l4-20020a17090ac58400b0026d0d2d1a90mr2912368pjt.1.1694624947292; Wed, 13 Sep
 2023 10:09:07 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1693328501.git.andreyknvl@google.com> <6db160185d3bd9b3312da4ccc073adcdac58709e.1693328501.git.andreyknvl@google.com>
 <ZO8IMysDIT7XnN9Z@elver.google.com> <CA+fCnZdLi3g999PeBWf36Z3RB1ObHyZDR_xS0kwJWm6fNUqSrA@mail.gmail.com>
 <CANpmjNNtT1WUpJu_n5x_tA2sL4+utP0a6oGUzqrU5JuEu3mowg@mail.gmail.com>
In-Reply-To: <CANpmjNNtT1WUpJu_n5x_tA2sL4+utP0a6oGUzqrU5JuEu3mowg@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 13 Sep 2023 19:08:56 +0200
Message-ID: <CA+fCnZdAUo1CKDK4kiUyR+Fxc_F++CFezanPDVujx3u7fBmw=A@mail.gmail.com>
Subject: Re: [PATCH 11/15] stackdepot: use read/write lock
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=g3MWeIjw;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1031
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Sep 5, 2023 at 6:19=E2=80=AFPM Marco Elver <elver@google.com> wrote=
:
>
> > Good suggestion. I propose that we keep the rwlock for now, and I'll
> > check whether the performance is better with percpu-rwsem once I get
> > to implementing and testing the performance changes. I'll also check
> > whether percpu-rwsem makes sense for stack ring in tag-based KASAN
> > modes.
>
> I think it's quite obvious that the percpu-rwsem is better. A simple
> experiment is to measure the ratio of stackdepot hits vs misses. If
> the ratio is obviously skewed towards hits, then I'd just go with the
> percpu-rwsem.
>
> The performance benefit may not be measurable if you use a small system.

I started looking into using percpu-rwsem, but it appears that it
doesn't have the irqsave/irqrestore API flavor. I suspect that it
shouldn't be hard to add it, but I'd rather not pursue this as a part
of this series.

So I still propose to keep the rwlock for now, and switch to
percpu-rwsem later together with the other perf changes.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdAUo1CKDK4kiUyR%2BFxc_F%2B%2BCFezanPDVujx3u7fBmw%3DA%40m=
ail.gmail.com.
