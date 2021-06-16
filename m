Return-Path: <kasan-dev+bncBDQ27FVWWUFRBCECU2DAMGQEPXGL33I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 63A3A3A90B8
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 06:41:45 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id 62-20020aed30440000b029024cabef375csf752328qte.17
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 21:41:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623818504; cv=pass;
        d=google.com; s=arc-20160816;
        b=U/BbZRnSR68Xqa5QAV6IEFKyKM8k7iKDpm9GgDzXx7SPniMOWHrDFbxvjjWyfnU2RU
         mEIKG2JPxxynuKQGNbCn47B6VeUQwqcTLQuFpuADmYhpI+vQ85406fRjwPc6MKUK91yK
         L1wxthdcNSrhjROXNzL2gSj/bOvJwL7WeM5IXxpMWif10Fmx2G+KhSCbWfnZ5hFobqZz
         5K6Zav1RgwEOYG7YHsWQbByBfwHA2cZcItLZ3XtCbrLWdP+C2nwj/gLrD84Kg+S7dGtf
         2EPfJmzK2AnGUzgB0s1zqABVqLFT1NkRa9HTCsMUCIDT45KuBTAoT/jjpsWmrPqYa6HG
         mt8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=aRIE3TYca2JznquEl+k0D/NbhbmL5YnQmpGr8F407JA=;
        b=Mv1JIM8K7xnOEZO5lUDegu+v3tYo0R2PbwXXBqXpDK0q921Ea7wuSEoZ4gLoFUWUbk
         7xKwoVUCzJOSr4TkEwxq3/k2JxDZ0ZGScfdKT/SmURiaxX3nBVCasoWeWFqr9qYyNOrW
         /rvZxw2c+JwXGtYCE/Um4atyJ6IrFeMl84h4xrhWhz/mCwvlAciZv5yai79VT0jzadr3
         ufmv4D2du5dOTicb19oGErstRuqfBVDIxB0nKOAGLAkXPZw/C1l7mMHGYNdxVzx9cNah
         8y4DtK3cuASOoT2UyGoNpKz4/jTC8SRcynr3e/xcQYfgV7lDHsglWb3m4tTF8LIKvj+k
         Xz/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=lKJIvf6p;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aRIE3TYca2JznquEl+k0D/NbhbmL5YnQmpGr8F407JA=;
        b=aHaboGI6YpG0DNtRxsEnVvGundCT+1s9m+AmBsg10zmaX3VeACX0ey+EEG85EDI8Hp
         kguiVr7wegYprKsB1OVWHidDLfuUSn45/JHaKh+ci76pZdxVvc+t8kVnxfbTrDrO5sQR
         5ZtKsJcVVFZ7puAdFCB0/abMcvyvP4F2pmQWlG0BaqCEwHqNsA96zlub7CYBsIsOI/wo
         Gg7WVmr2W8A5X5ZuqdupGF4FgkCMrpQU9Fy0c8uwu1IYLGUjxVeCMjspBBCSPylFnRiw
         XCcZ16WVeQ26wfdVGKAHGJGeSDuuGNscJooX75CIQsvCR4D55lNZM+D8P30TmO5r7sqT
         e4rQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aRIE3TYca2JznquEl+k0D/NbhbmL5YnQmpGr8F407JA=;
        b=UeudRFlxG50ab7iPAnzyyhb992mjUMfJziEymuJT4Z7AGngqA5mqco0bS4SXOTIgcZ
         gJsthRLRFqHRLizg+CgHfAVy3BWbgLLhalQe3FuoQQPO/WcE1C8gQxDi1jHtP7HW/dme
         TF1hiJO1fir/7OOhFAXYFJB8zpjZbqhvUlGkozbd1tfFBWoMhJoV2TmvX7nC9lfUboKI
         yLp0VmF9eKd3FtccZsc5YAUqZG/EjjmgfBaKpEyx8qvmHqTScPpSk2vI3HH9O/gUQ+m8
         x9cEasnzUtGbCwu/hkQ01Mv/il5n+9B0gY6a2qYtgg1fJ9nDs2rQuHpAgtLHBsSmhRzM
         VF0A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532R5bz19kicZH3ff8SVUXbY6/5ql5+KceHBDD2ZqpP79OJ/sy3p
	gFMGoyYtkX+JSrZHDDco86Y=
X-Google-Smtp-Source: ABdhPJyQ6dzSxJliU+PrFs/CTVqyBJzTu422A/tcJJP14E06alDnlTl30n+gpCFGWX1KP8csx01dEg==
X-Received: by 2002:a05:620a:12e6:: with SMTP id f6mr3132055qkl.420.1623818504314;
        Tue, 15 Jun 2021 21:41:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:17c2:: with SMTP id cu2ls326766qvb.8.gmail; Tue, 15
 Jun 2021 21:41:43 -0700 (PDT)
X-Received: by 2002:a05:6214:1d0f:: with SMTP id e15mr8990779qvd.40.1623818503907;
        Tue, 15 Jun 2021 21:41:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623818503; cv=none;
        d=google.com; s=arc-20160816;
        b=ceW2rbuXnP3elKYJ4bZ+skagNPZNEOQoBQCX5hKm+q4XG/ZS+HaJyitxpZIapjTdKp
         CCOQvo5ThDLKgYNVRpa2ZKuavTLC4yiDIlBdzI5F8dBO7wMV956A9DjsCwOWkpMsvQWY
         H0/E+PJ/LWoVUoD7RrVjvRT3pzsI6CJHR2ybaSPp4P4S2XzKoloWt26DhpMZp8iTmWEX
         p4YzOfNIYFnhU+nNQLFO0stMVJ6CFb5rY8wRAEfmNACfHQ3vGayMMk6Kp8nfqAxcPmj+
         Vzt6vq0hL+t06g9Ke6y0Vm4pCVAy0NFkrjnLN8TUo5Twsn3Fmfas3pFJdETWyVoHBBj9
         KdCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=yNLs0De7jThuF+2jQNPxEWOcx6TgeD4ov6vuIyTpd+A=;
        b=B4W0B/MFOBkiV6ZkOebbCtN+4/KqOZhWXwnjdxXphS1DGT0I+TL0/qoXOYz51RcUgn
         VVJtuqsr9xs4HJ8be1hw10dG79ZpepUojm0Mx6heGQ/sDrvelo6ELH+GWRKp7QaR/aXI
         pL9+dOhLJjn3DKeTy4+avKrsutGKaSftJ0MUbd7ItfV91oDwjr7LF2U7Oa8qryaUgzJR
         XPiJi1m+STseUuT/WhkATQ77jjHywXFzvAZGD/gs8wJlu/ddhdZjilGnTjNnAFqdDyc3
         S6O7i2NN/3Ava0rs+1OzhA160Qm2nwBtsOfkvV6nqJmAkZfNuDWCR+hlCxsBzqUxKlhL
         Qvjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=lKJIvf6p;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id o23si88368qka.0.2021.06.15.21.41.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Jun 2021 21:41:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id e7so476828plj.7
        for <kasan-dev@googlegroups.com>; Tue, 15 Jun 2021 21:41:43 -0700 (PDT)
X-Received: by 2002:a17:903:228e:b029:101:af04:4e24 with SMTP id b14-20020a170903228eb0290101af044e24mr7415002plh.3.1623818503317;
        Tue, 15 Jun 2021 21:41:43 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id v10sm726962pgb.46.2021.06.15.21.41.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Jun 2021 21:41:42 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Marco Elver <elver@google.com>
Cc: LKML <linux-kernel@vger.kernel.org>, Linux Memory Management List
 <linux-mm@kvack.org>, linuxppc-dev@lists.ozlabs.org, kasan-dev
 <kasan-dev@googlegroups.com>, Christophe Leroy
 <christophe.leroy@csgroup.eu>, aneesh.kumar@linux.ibm.com, Balbir Singh
 <bsingharora@gmail.com>, "Aneesh Kumar K . V"
 <aneesh.kumar@linux.vnet.ibm.com>
Subject: Re: [PATCH v12 2/6] kasan: allow architectures to provide an
 outline readiness check
In-Reply-To: <CANpmjNN2=gdDBPzYQYsmOtLQVVjSz2qFcwcTMEqB=s_ZWndJLg@mail.gmail.com>
References: <20210615014705.2234866-1-dja@axtens.net>
 <20210615014705.2234866-3-dja@axtens.net>
 <CANpmjNN2=gdDBPzYQYsmOtLQVVjSz2qFcwcTMEqB=s_ZWndJLg@mail.gmail.com>
Date: Wed, 16 Jun 2021 14:41:39 +1000
Message-ID: <87fsxiv2t8.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=lKJIvf6p;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::636 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Hi Marco,
>> +       /* Don't touch the shadow memory if arch isn't ready */
>> +       if (!kasan_arch_is_ready())
>> +               return;
>> +
>
> What about kasan_poison_last_granule()? kasan_unpoison() currently
> seems to potentially trip on that.

Ah the perils of rebasing an old series! I'll re-audit the generic code
for functions that touch memory and make sure I have covered them all.

Thanks for the review.

Kind regards,
Daniel

>
> -- 
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN2%3DgdDBPzYQYsmOtLQVVjSz2qFcwcTMEqB%3Ds_ZWndJLg%40mail.gmail.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87fsxiv2t8.fsf%40dja-thinkpad.axtens.net.
