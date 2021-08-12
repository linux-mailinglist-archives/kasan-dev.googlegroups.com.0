Return-Path: <kasan-dev+bncBC7OBJGL2MHBBY6B2OEAMGQE4RWPECI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 966683EA0FD
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 10:50:44 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id p21-20020a1709028a95b029012c31764588sf3318684plo.12
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 01:50:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628758243; cv=pass;
        d=google.com; s=arc-20160816;
        b=uE/mBzrruS7KixU3rUAqLX5SLrG4db0gQ7DPyf6mA+vQRg+AxNJKjT9lyqj/vZ0SL5
         DfBvpKCeMl75Q+pU9A1cb1HVk/JSLja4tdxmzwvp2lkCLb42dTN3+zR1YVvQvqaQxdoz
         qtFfYeR3xlxaue5ypBiEmVId0pp5EZSR4Is56uA+DCNTLr6ns+Tmva5pr8HNAzvwA0Im
         IpXgGWaPfPk0RnR5b6EGJ1hiV0EYo/pjOViM/cJ8E+SMYuoSVb/my6LO1kCa+cwetEfk
         CDCJwG+OeAdGSOoOz+mjFg5iUZSJNvYtmShRyUqtDla5gSxeGs/p2JVoT+3foK5cZ/3o
         /0Gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=iMD1gPFmBoJzdrMngZ+5IP40wjBJfW+0mMK5InYX/5c=;
        b=Nir5gTjhHyuXFBizgsEKMpQeI6XJ3yDksMKYXHc5QmE63/MiQ0iF+H88xoZF/hGyfF
         iYzkwwl1QVpz6uVbQuKiOG83I3AVMQW6JhRGPb8UCRKPHdnEXSH+UfMC07rsWH4dZgM9
         56wx/xqruTvm6ukXd00UhdsAJ7O4RtVawbb2HywOt1rCPpoolfN9RoVJuSdQsUkeLwIx
         S/eMugaqFV8u22aVtrF/kly4NyReyH2GDhk8FAe359aXCeE2rQhc7+2e2dsrSgtzE2Y3
         w49Iva5oh/xO/Va68U5pLT+5Mz9DlPT5Eyg04fTuvd3Ope5dl9OU7QK42HwN2dtKbYzz
         6+0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Dw7WCJKV;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iMD1gPFmBoJzdrMngZ+5IP40wjBJfW+0mMK5InYX/5c=;
        b=dK2HsrfrVyGT9BHn+IccGUx/L6HYa9vd6GFtIn9fHUywxiQoBX+kje8zATD5lIVh0P
         7KoDeiqjGki31snW1BpBE6zimMiBGkvS9qyGgS6OpSFN+E+3t4sM43vbrktnZ6HXeQg7
         biO1p5+dhwhniPFASaU/OWenn2Ad/QWYCBOwH1LdViOxezBBCCPchO1pVLoRVsNHqFez
         /DKEaui2tU135wx8+ZM6cxwMakx9Beg3gXfDGpVbN8Dl+KKuH9Fdri5q7PqgEDlf17KY
         8RIuW74M2KGF/SG9iz8ROYqWBkpxiI+VxCKipKnr8Qn5yjlSXUxm2OphYbxpnJ7sfmPL
         N5+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iMD1gPFmBoJzdrMngZ+5IP40wjBJfW+0mMK5InYX/5c=;
        b=iLTdppV6OvWLXI54i/AmlR7VXQwxsWlXxoV5x05AVXfamHz+AiwckTv4JNX8jvnobj
         Kux4NMqJlfnrCktb38fVMivMGBgCMAU/4mofGRh7qPsCFmbaaq8Ea53r8+siIZ6h07nV
         1xvsLwE/w/JIn/Z8gCx7t2zZuqKlSMWfKs9P9Y0j+lAGIl6LPFjtzAJLwskdRcSvME4B
         3p3jelpwILozklCIw5bHkAwDwFcDgZ09FiybDIPBYgo19NBFZuB749I3W17XIifHm2+q
         XrypXCHJmj07DCm/bi2WCfYSVHRItwl1dHOgQBWyyRfYE1ZzG13g+ICjn9hx4nLj0ds9
         ELuw==
X-Gm-Message-State: AOAM533QatE/cNJDQ/UpTxo0dLU1l65tgtBAmLo9nh6RybNUqelD7/gz
	W3C4+jV5NQzcdCmcqwFwT/w=
X-Google-Smtp-Source: ABdhPJw9wlQynl3ZSDEDXV04U9HSQYkTj+s/pBxRzrxNVHJ4pqJqnSPkSnvvwt2ZFEhsp+04RJ9jHw==
X-Received: by 2002:a17:902:e84f:b0:12d:830c:97a1 with SMTP id t15-20020a170902e84f00b0012d830c97a1mr380315plg.27.1628758243231;
        Thu, 12 Aug 2021 01:50:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:360b:: with SMTP id ml11ls4730196pjb.1.canary-gmail;
 Thu, 12 Aug 2021 01:50:42 -0700 (PDT)
X-Received: by 2002:a17:902:7885:b029:12c:437a:95eb with SMTP id q5-20020a1709027885b029012c437a95ebmr2751006pll.80.1628758242505;
        Thu, 12 Aug 2021 01:50:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628758242; cv=none;
        d=google.com; s=arc-20160816;
        b=iqjtqlWeGdUsB1na1cUnPi2XAz/ow2+N/L4jZtgmfRrnFky1uizf0bZzu2euX0bRT4
         +jsbcvIHrDgYmhB4FZB8+4cMDwPwbYFukiL5ZhF8lNGn3ZbI/8F8sxK25/sWKFwWS38v
         Wuiw/bLk/PE6N9cYV+2zeyLnJgWBHMApKquGj+I5OXrfdUyjpYwidphlhQq6mcnVsi1y
         qKbpXUNCOsU40ZKTf1lDJwvvN8wsiLwH8jMhTs6vS/UFsQotDAIdsBTq4hegKip8d1hb
         Ih48qFEYmT3K51Lhm5OdxFPhv9nE+oAcBJft8YLuSoFFEh/tiQjhG5BUmoteZiCM8wjE
         ml8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AFyPNO4ZkizLh3L5gPVy35vzpqSp3wuB2t4x2aRMQPw=;
        b=Z8T/gDe2woCCogH1yLG3Cvq821wpXD4PUS7CyT2x6525HS3z/BoPz6oY85Q359nJo5
         S9DljtrgadP3m7RlwX3Xaj39nLkJYD57jOHN165A2b4obPliSJRb6Xg7DWK5Ncwe+LVb
         cvBl8XlAm90lr7C8muDOGp5DDtG+HnlKDm5effpB63aHCJ0o5VhzXnR9DpClZvxXgTTG
         LslNCFEYA7Kge6kW58Of3Z5auXFlm4DCEk9msErcQ3TehxqrPTEUVhWghBbtVulND49c
         NIG+U1n1iuvfexmXAD5ZDJTVP6eRjbCfJHMT4VePtMVDMoG+GubKSmNjCdbjMa/o7xpx
         OwKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Dw7WCJKV;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x333.google.com (mail-ot1-x333.google.com. [2607:f8b0:4864:20::333])
        by gmr-mx.google.com with ESMTPS id c23si114890pls.5.2021.08.12.01.50.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Aug 2021 01:50:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) client-ip=2607:f8b0:4864:20::333;
Received: by mail-ot1-x333.google.com with SMTP id r17-20020a0568302371b0290504f3f418fbso6807341oth.12
        for <kasan-dev@googlegroups.com>; Thu, 12 Aug 2021 01:50:42 -0700 (PDT)
X-Received: by 2002:a05:6830:1490:: with SMTP id s16mr2619178otq.233.1628758241746;
 Thu, 12 Aug 2021 01:50:41 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1628709663.git.andreyknvl@gmail.com> <da8d30df9206b54be2768b27bb026ec06e4da7a4.1628709663.git.andreyknvl@gmail.com>
In-Reply-To: <da8d30df9206b54be2768b27bb026ec06e4da7a4.1628709663.git.andreyknvl@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Aug 2021 10:50:30 +0200
Message-ID: <CANpmjNOf=XzX1xhjaz7+SBN2HYq+9jH4EcHi4gfwjSyTa3q00w@mail.gmail.com>
Subject: Re: [PATCH 8/8] kasan: test: avoid corrupting memory in kasan_rcu_uaf
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Dw7WCJKV;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as
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

On Wed, 11 Aug 2021 at 21:34, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@gmail.com>
>
> kasan_rcu_uaf() writes to freed memory via kasan_rcu_reclaim(), which is
> only safe with the GENERIC mode (as it uses quarantine). For other modes,
> this test corrupts kernel memory, which might result in a crash.
>
> Turn the write into a read.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>

Reviewed-by: Marco Elver <elver@google.com>


> ---
>  lib/test_kasan_module.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/lib/test_kasan_module.c b/lib/test_kasan_module.c
> index fa73b9df0be4..7ebf433edef3 100644
> --- a/lib/test_kasan_module.c
> +++ b/lib/test_kasan_module.c
> @@ -71,7 +71,7 @@ static noinline void __init kasan_rcu_reclaim(struct rcu_head *rp)
>                                                 struct kasan_rcu_info, rcu);
>
>         kfree(fp);
> -       fp->i = 1;
> +       ((volatile struct kasan_rcu_info *)fp)->i;
>  }
>
>  static noinline void __init kasan_rcu_uaf(void)
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOf%3DXzX1xhjaz7%2BSBN2HYq%2B9jH4EcHi4gfwjSyTa3q00w%40mail.gmail.com.
