Return-Path: <kasan-dev+bncBCU73AEHRQBBBDVWXKXAMGQEAVFGZ3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 092F6857144
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 00:15:28 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-290a26e6482sf126966a91.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 15:15:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708038926; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZSp58SUSD9mzxeOxO6mupIGDIK6cYZD9zxGdYJXrlF0TvXJysEAP4q02zrimTQImO5
         PgB2RpE4ZECuZgQj7IlgDA5+iJ/duNKegVAb/aEL6FpXnCd8LSELnf0Ab0FWLfdN8sZD
         ucRBr/i8ddtBsBIxeww7GBeAkdxgfEhvvEwCiyn1MjRfO2CpwKSRD+VhsiasnvybXwPp
         DmTrN0rcH60EsOq4CNBWmiwCAMhqEb6z4JaIv9LQ+WA+w0pA1pivrV/u3yc0Cg7MqfSI
         r+YuRvpDaFInVmZA22Nlqq9DS08hD2qfpceTirf7HsUTmvB8a6KRBLwlz7EE2tzPJfsy
         1XVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=zM7J1zcvGdYd9CZNKfvJEmqZJfEfQlHKODd4PX/iEHg=;
        fh=JEtpBtaQ3LBgsXdBvYkTRSOPJNTn5p1rHQIE2v9NpOg=;
        b=T2Rp4WwuVREAq9/LnDuzQI7VcBXJyw1qSwEsMA72SDLeYAn1HApLrIfMDxoaapIndn
         xmGTl3m8ZY3cgwZstCwz1bB6FxVz/w3gCPeXPuAwEkCjtkkgJW2nkZpFaGEbTxLvPYoy
         +/JCcu0N+tiVpJYCbdyHg3O8uwIp+XIO4osm4f6DR7XMLCLfpacXZJ7rKnvoTuqmyteL
         Mfc5JPp+JzDYf7uWDFivSa9+OiDskgCKPZYt2TTzf9Svek4rXpwvMvgYBAAa71NnxIZp
         0LFPBPUJ8WAkRru+tEQognfXk9P+80gS6SKchcUvConj4qj+ms+hIy79MAAZR0mIBJ4L
         761A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=ydmf=jy=goodmis.org=rostedt@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom="SRS0=YdmF=JY=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708038926; x=1708643726; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zM7J1zcvGdYd9CZNKfvJEmqZJfEfQlHKODd4PX/iEHg=;
        b=aPx7h+qnbSiF9nSWsRnL2ce8W9EKwme+MYf4t7F1dSWDrz6uCTp+nIqvmGV3y/QWSi
         SYUdvKUUncTAHfEJboTdJqV84/ZO19mk7UZrXmDe/EN2JsYcK8VwTq+wJ7krtn0W+Vra
         gh0VltbI/xQTzmy9uVGn9YqNBzYrU1irTs4K5EvMurwOUG/H/6qVbL3yOrqixlVQj9SN
         DUWu5qCL7D1JuMfdLhq+HyeHYzbqRGnW1fcNULK+EC8p+jt9mMay4KOnKB8Mc9X/0W4I
         0vFvEFD2T0Llsc12ax9d8nbEvaKS2iIw19x7H3t0VAeeDIw/Tc80xDNQ3gdpNh9Cs4YJ
         RiKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708038926; x=1708643726;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zM7J1zcvGdYd9CZNKfvJEmqZJfEfQlHKODd4PX/iEHg=;
        b=gw/1PjERemuMQ2E0Ma17wzrPZ/zE9xX9EL/k0XUttSYAPq+HJvntbkPK5cZbIGa4ju
         wp54HG1nIVVkkkXioeQjFqvCPMFfrd3crSC0Jthbo4NUDPmtUGAHB7pATiQUqTYde9lQ
         x7yBxzZAHhXe9CdaXrhvFZ7/vS1q3g4lenxGqgyIuqpo+Xb2jsD8WgkHPJc9L5dA+SXz
         JfS5rTtJImGQnY5NJR3+5kYkLzqL8zOOlFB7PN9qvkqkBOf8TTnHR21vmPsL9/cUWOaQ
         zb8APNboLU13NFrfzFlIpreh39j8NsI1zEaRDTOTyw3U5DB2VrJUDYZtkgeRSGd3pX66
         EAcw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVU59RUZ3F+YVBbXRS1JOafw/fHwtLBYOVztrUNadb4Rn4NQPIJUtjLAPMQV8O1ZUCITaa4NECb3NOx90EEV2su3GaBPfI3Fg==
X-Gm-Message-State: AOJu0YzEoPA7q8uO6DVnnuWlnSWDoF/cz46OlwcBB/14fJGj0f/AB4KS
	GC0aOBjZknRcMRSGCQX+OVcjT/0XcWz2hoKsvVtukWFXdgdunGw1
X-Google-Smtp-Source: AGHT+IGfBqlNskuKALGjs2GB5EdNdThU9PAohQ4cBu3Fwlc5jMlITb02s9EIWkv6ikoKnKPh964eVw==
X-Received: by 2002:a17:90a:bb0f:b0:299:a6b:16a6 with SMTP id u15-20020a17090abb0f00b002990a6b16a6mr2734778pjr.11.1708038926297;
        Thu, 15 Feb 2024 15:15:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3d12:b0:298:d44d:198f with SMTP id
 pt18-20020a17090b3d1200b00298d44d198fls220260pjb.0.-pod-prod-03-us; Thu, 15
 Feb 2024 15:15:25 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW0dmik0KfBjKPIZCjTYZ4qh3mE0jYKWyW0MHvWzLpP6kcNvU2KGYoxSjv2vpgwFLFXymJOk0uuK79/FagaZOzb8qXTMmr9JA2ClA==
X-Received: by 2002:a17:90a:ea0d:b0:299:2f6b:104c with SMTP id w13-20020a17090aea0d00b002992f6b104cmr853212pjy.17.1708038925093;
        Thu, 15 Feb 2024 15:15:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708038925; cv=none;
        d=google.com; s=arc-20160816;
        b=VMmDYUqdjBVno7Zzl0jZ16SMXzl6VM3c1SQwoGktVVsSETZewsxgBNeaO3OeyDaps+
         M1jjUEtn2og9kA6SqjX91rZutG4htLqErgHBmWtL65Yt+dw+NQsBAvPF3HR+WoyvdfIf
         ZjGxasSQOAcJbxvGQGsvJjVf5kyq/GW3RpttlJ2AbCkAolGtdyTpJXsth8JPCnx3YTLr
         c/TgOeiS7WK7OWd6CBvJXG35d8K2BT9g/XcfRrD3v/JMgrQJ8fl56PlCngaOdTbPoL9B
         D38fWm5ofDvcqto7HY4H1+JsKjPwnpYSQwLie8khAL50mlMkIFJ7O+07au0RFhu+R9T6
         MIJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=Qp6dBo8TIOWe+z2EYinfAxQCNXTbCZlTX6RUIQ/0wW8=;
        fh=yAsR8mz6OHt7FqUIcMxTq2xSLRkYQrfOXi2SdkYqlko=;
        b=0aF6RhUj7Ea72j4tmJqkLzOtopLunpKQSuL47K2D7rulZZKMxy4IyK9CUmjAnbsb8x
         ofHuJE8moIS/RxKtbLFlW+d+Vw9atmvY5jVpS+1aACPvq9PTjdnRebJ2TOlQvpDZOR95
         rl4AmJPVpFBK4W4YEPytnLntg0owwGhld4sRx6fkLa+YdhRS4KfTXfY2LbpDVuxNLa76
         +xXvevS0YpY+fPTUiO+tS8lr1/NhCrOGp16pMnUuP3il93ChkY2E9jHf61tfE1r5apsZ
         XOM+H0wgv+VydZN4vxEFMP+YUdeWKYoOr2CaCmDvs5/Zlzw73WuiIX0S2p4jEm28w3Vm
         WiQA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=ydmf=jy=goodmis.org=rostedt@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom="SRS0=YdmF=JY=goodmis.org=rostedt@kernel.org"
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id l22-20020a17090ac59600b002971d0dc19bsi267483pjt.3.2024.02.15.15.15.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Feb 2024 15:15:25 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=ydmf=jy=goodmis.org=rostedt@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id A8E30CE23E2;
	Thu, 15 Feb 2024 23:15:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 97C9DC433C7;
	Thu, 15 Feb 2024 23:15:14 +0000 (UTC)
Date: Thu, 15 Feb 2024 18:16:48 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Vlastimil Babka <vbabka@suse.cz>, Suren Baghdasaryan
 <surenb@google.com>, Michal Hocko <mhocko@suse.com>,
 akpm@linux-foundation.org, hannes@cmpxchg.org, roman.gushchin@linux.dev,
 mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
 liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
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
 dietmar.eggemann@arm.com, bsegall@google.com, bristot@redhat.com,
 vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in
 show_mem()
Message-ID: <20240215181648.67170ed5@gandalf.local.home>
In-Reply-To: <20240215180742.34470209@gandalf.local.home>
References: <20240212213922.783301-1-surenb@google.com>
	<20240212213922.783301-32-surenb@google.com>
	<Zc3X8XlnrZmh2mgN@tiehlicka>
	<CAJuCfpHc2ee_V6SGAc_31O_ikjGGNivhdSG+2XNcc9vVmzO-9g@mail.gmail.com>
	<Zc4_i_ED6qjGDmhR@tiehlicka>
	<CAJuCfpHq3N0h6dGieHxD6Au+qs=iKAifFrHAMxTsHTcDrOwSQA@mail.gmail.com>
	<ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
	<320cd134-b767-4f29-869b-d219793ba8a1@suse.cz>
	<efxe67vo32epvmyzplmpd344nw2wf37azicpfhvkt3zz4aujm3@n27pl5j5zahj>
	<20240215180742.34470209@gandalf.local.home>
X-Mailer: Claws Mail 3.19.1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=ydmf=jy=goodmis.org=rostedt@kernel.org designates
 145.40.73.55 as permitted sender) smtp.mailfrom="SRS0=YdmF=JY=goodmis.org=rostedt@kernel.org"
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

On Thu, 15 Feb 2024 18:07:42 -0500
Steven Rostedt <rostedt@goodmis.org> wrote:

>    text         data            bss     dec             hex filename
> 29161847        18352730        5619716 53134293        32ac3d5 vmlinux.orig
> 29162286        18382638        5595140 53140064        32ada60 vmlinux.memtag-off		(+5771)
> 29230868        18887662        5275652 53394182        32ebb06 vmlinux.memtag			(+259889)
> 29230746        18887662        5275652 53394060        32eba8c vmlinux.memtag-default-on	(+259767) dropped?
> 29276214        18946374        5177348 53399936        32ed180 vmlinux.memtag-debug		(+265643)

If you plan on running this in production, and this increases the size of
the text by 68k, have you measured the I$ pressure that this may induce?
That is, what is the full overhead of having this enabled, as it could
cause more instruction cache misses?

I wonder if there has been measurements of it off. That is, having this
configured in but default off still increases the text size by 68k. That
can't be good on the instruction cache.

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240215181648.67170ed5%40gandalf.local.home.
