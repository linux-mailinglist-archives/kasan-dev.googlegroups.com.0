Return-Path: <kasan-dev+bncBCLL3W4IUEDRB4HZ3SXAMGQEYXTOHFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id CDEED85F80E
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Feb 2024 13:24:18 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-2d256d36f6bsf15100841fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Feb 2024 04:24:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708604658; cv=pass;
        d=google.com; s=arc-20160816;
        b=MfshNsh0mgVKv9QrY4m5kFp9CTeNg8nEhJEbLGLH1ZrhUkoz8XETpb8TOd72FknA7Q
         K+PklMb2u+AqP+x8ZsyfhJnKlM/qHoW6E19VENnmBK/x04gsxC8XLzc3hoJwGSJ7anXG
         +tBHMZq/XD2d++mVaIwq6q0kSHpk67BLvxWCbRJlaqjaxNdau5ahUd0fo8z7CCqaiIzA
         e57VBoL53qlM5YhJi5qtYXCzq45wct8JWCo5VVI7sSkX66+YNghbLgZ0m5G2Hx9Y3sf0
         0cvR5y7+i2SvWNGEs/v+VdMNNUF66+0t14bswz8pWDDtDl+ayMN8Y5NZjDSfj2jxpyBD
         8i9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:dkim-signature;
        bh=IH4kCoS7UELqbrsCaQxAaFRCsIXf8c4XBE2JsZPo55Q=;
        fh=hhfvyxGxhZxA7hbW/CmPWBkpw/HH8IbjLYnQI8N0J2E=;
        b=QHxT3yUtOawhBxIFNZCzq+Q3m67r+czEAfQ72rLdcsMG8cnzLZae+z+AC9X4MBgEjy
         lwJAQk5QbDrWgjNPCsyjA7qQOI/wGYEjbr0L5SBuL01kLw50f8FZ27YDVxYXeD4Kwz8n
         XwKllUNQgi7DHrQH8SFdT5fIYNBZILIOs+xdKiuLfZqDuosBkS7IigXoEWOr+ejEZ5XZ
         Vhgv2cCWLyA3LMFRDdD0HCMKdC9CJZb8lj6o78MSyZLsWHeFOmp3f2Oc0op7YZG9rid3
         SZpatDPZNY6ZabEtTq/pm50Hy5Mxj7ViqLEhsglbqSFVP2K4KbxG2s/nm4aR4LX9p/wx
         H7wA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=EUAlNGrf;
       spf=pass (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=tesarici.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708604658; x=1709209458; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IH4kCoS7UELqbrsCaQxAaFRCsIXf8c4XBE2JsZPo55Q=;
        b=HW+CpGbXs4bPofdfoXSS6NhfJmSne0M+7/RoyC+npHtgMeFYAqhXndIc2Oel6RwjnV
         gV0W0ZsN170b4uglCBAKAx4ddwL73pD0KqxQPZhdmK0te95Wg36BATdUodzbAqRHJVt7
         HOAzd+Lt29HE23Q2XDz6KMIyVjZAKrsbagp6MkwoVETzE43vCLhJHOR//iFey4ckyahz
         p8P9RTWP6PhAjXLiI3sAcYsQSihaLUtDG34DvmOserI/fRdxhoZSESSIv15frF7Rd2C+
         g9VX3Q5q4QDC/sn13zdpXEFdW5axGOc6l0V84GshK4fOMmGrKJq4YiU1/DY70F1/DKLE
         PWYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708604658; x=1709209458;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=IH4kCoS7UELqbrsCaQxAaFRCsIXf8c4XBE2JsZPo55Q=;
        b=pgri/SNKKXfj+lNDKdwspOn80obP0kEnyysUMRSRwGR324FgdyxxolhQF2us6QOdY0
         OPqV69kanD5icapIGebMsJ+vDGDMo6Fzc/BtVCgOAVBM3BhdbDYjNrn10VmUDuFUyZ9U
         /uXyTBmSFnykFAp/CKThxdel7LB6GxCiKJSfnSwvdnPMuouw8UJBFKaAMUOKQx6Die8B
         rW2Bpj6jO9Wg3h4X/rhEQRdU/NWZxJGO1ggldwApcDbrJ9iyDied2W6W6wo+lypCkBgy
         MgtnZYhKzGAUxPqSI1OAtoMWiQHUskq6HudKWSyZx2Dg5G/fUWjXSLq1/ZyIAntlDqWM
         AZcA==
X-Forwarded-Encrypted: i=2; AJvYcCVpgzlADJSJUZLoqJ61aHFQ8vpJrFkYuLFMDEvseZmPMI0dq0mDoY4UsgX1rbU6ODGp3LMmAy9CfDDk0EPb9R5yR+hY3hs0lw==
X-Gm-Message-State: AOJu0YxiIsRZv0WGAeFybZ82DmJyYd90Y8j27jIh5nhyenI+j8L865F2
	9XVov5RW9ZBN71IpJM70IvnQhZIOXRr9wLDTbEPv8Rdnxu8+0yzO
X-Google-Smtp-Source: AGHT+IEE2u51Wx7r7mofXXRm1UaCtPqqqGJ8jJNv6KS0N9RMyp8ESIwg6k8jFGVJBZM+WwDTz7ph7g==
X-Received: by 2002:a2e:a54a:0:b0:2d2:4cb2:59e0 with SMTP id e10-20020a2ea54a000000b002d24cb259e0mr6018418ljn.46.1708604656881;
        Thu, 22 Feb 2024 04:24:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a4ac:0:b0:2d2:380c:3d01 with SMTP id g12-20020a2ea4ac000000b002d2380c3d01ls1076571ljm.0.-pod-prod-07-eu;
 Thu, 22 Feb 2024 04:24:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXKHYhcNhDpc6UGqbdw7ZewlVefmhFFurHB9VOuTeK8H+qULFXVK0OuT4WRJSj5UmPOYtxAs5uzLIsWtWIry+bqMeEGms4rwfbcmw==
X-Received: by 2002:a05:651c:1a26:b0:2d2:4450:92 with SMTP id by38-20020a05651c1a2600b002d244500092mr7576445ljb.20.1708604654929;
        Thu, 22 Feb 2024 04:24:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708604654; cv=none;
        d=google.com; s=arc-20160816;
        b=Z97ZX/ZnLR+iUa19xpLwHqLB5yq3/YDLyPKUGhwU2LblC4HqCwz+y+HZPEvZJ5nk5m
         V73zO0CKb7eW9VzgugXGK31aALVIgwbriHa/OR+n4Iiz3p3NFZOBCAWNvfYymAoWF9va
         96tRyW3TQoVPkUyFAtK/q5nhant/VIoNR5hQBNcnXOYvS3MewvadlGyrKxsLkeTvXaAl
         RZzGegmE2ntGL4V3ND005FP4XiOmOHF6nsbmrJlmVTEZu6dULmog24/KQPfVm79peJaY
         xjQ5gIYYT25z1rWCLAwj/oCgnDCA29YD8/ZFSP5+9k/Xhd5ra3Z39L1PFGCUihb0Lyyw
         TcZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=SzkRLezEcoWqN5XMk5IQjv+zaBzCE6hGL4TlzpzvRx8=;
        fh=M2TDT1pKaetSRjmfVRGty5cIvZ69RRvvUoZHcxAFNMA=;
        b=Bv1NSQkCOBnZD249yY54i772e6SoIGcdwRAXwZys31113NkJMTmMfGHDKmGxbWbiMa
         5vKzs4TNlTUb9glDdtDRWRI1R3+VNNstmoUYaJNaJ1J3D/Gu902yVenvVZ0B6np+JRvt
         oIPanybgYUyIDWCSr5+vQPsr+BnUV1O8bCpupkLAlX/e0fW9jUtZVRAo5dWFGWlDNp53
         cNbu9rYPs/jRJmWEaPwXSfVjOln+JUeOM+iFfRrBvQGbAlQp1amiX8WsEJoyPBDzrI1p
         xoIbg+iKz5kquphce6yRGzEsERAImRA5lOW1AN8aRYB3f1hcTRfpTcmyQB4tpb74mJVU
         8G+Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=EUAlNGrf;
       spf=pass (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=tesarici.cz
Received: from bee.tesarici.cz (bee.tesarici.cz. [2a03:3b40:fe:2d4::1])
        by gmr-mx.google.com with ESMTPS id b24-20020a2e8958000000b002d230e90c7fsi516572ljk.5.2024.02.22.04.24.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Feb 2024 04:24:14 -0800 (PST)
Received-SPF: pass (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as permitted sender) client-ip=2a03:3b40:fe:2d4::1;
Received: from meshulam.tesarici.cz (dynamic-2a00-1028-83b8-1e7a-4427-cc85-6706-c595.ipv6.o2.cz [IPv6:2a00:1028:83b8:1e7a:4427:cc85:6706:c595])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by bee.tesarici.cz (Postfix) with ESMTPSA id 49C831B3C16;
	Thu, 22 Feb 2024 13:24:12 +0100 (CET)
Date: Thu, 22 Feb 2024 13:24:10 +0100
From: =?UTF-8?B?J1BldHIgVGVzYcWZw61rJyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: Michal Hocko <mhocko@suse.com>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
 kent.overstreet@linux.dev, vbabka@suse.cz, hannes@cmpxchg.org,
 roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com,
 penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
 rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
 yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
 hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
 ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org,
 ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
 bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
Subject: Re: [PATCH v4 06/36] mm: enumerate all gfp flags
Message-ID: <20240222132410.6e1a2599@meshulam.tesarici.cz>
In-Reply-To: <Zdc6LUWnPOBRmtZH@tiehlicka>
References: <20240221194052.927623-1-surenb@google.com>
	<20240221194052.927623-7-surenb@google.com>
	<Zdc6LUWnPOBRmtZH@tiehlicka>
X-Mailer: Claws Mail 4.2.0 (GTK 3.24.39; x86_64-suse-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: petr@tesarici.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tesarici.cz header.s=mail header.b=EUAlNGrf;       spf=pass
 (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as
 permitted sender) smtp.mailfrom=petr@tesarici.cz;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=tesarici.cz
X-Original-From: Petr =?UTF-8?B?VGVzYcWZw61r?= <petr@tesarici.cz>
Reply-To: Petr =?UTF-8?B?VGVzYcWZw61r?= <petr@tesarici.cz>
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

On Thu, 22 Feb 2024 13:12:29 +0100
Michal Hocko <mhocko@suse.com> wrote:

> On Wed 21-02-24 11:40:19, Suren Baghdasaryan wrote:
> > Introduce GFP bits enumeration to let compiler track the number of used
> > bits (which depends on the config options) instead of hardcoding them.
> > That simplifies __GFP_BITS_SHIFT calculation.
> >=20
> > Suggested-by: Petr Tesa=C5=99=C3=ADk <petr@tesarici.cz>
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > Reviewed-by: Kees Cook <keescook@chromium.org> =20
>=20
> I thought I have responded to this patch but obviously not the case.
> I like this change. Makes sense even without the rest of the series.
> Acked-by: Michal Hocko <mhocko@suse.com>

Thank you, Michal. I also hope it can be merged without waiting for the
rest of the series.

Petr T

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20240222132410.6e1a2599%40meshulam.tesarici.cz.
