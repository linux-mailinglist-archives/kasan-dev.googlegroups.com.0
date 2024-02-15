Return-Path: <kasan-dev+bncBCS2NBWRUIFBBLVMXKXAMGQEWGCXF3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 978B28570C8
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 23:54:39 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-410e860c087sf531225e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 14:54:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708037679; cv=pass;
        d=google.com; s=arc-20160816;
        b=0I/NQKv4ySeLj4DaLPTBvBQ0KpQOH2SmQzbh+jkVFiyYDAXBYjElkcAmgafI6mMtpA
         de9AOK3ET6gozs5Vlb3RVOjyYluIqx2d7QB4gm5OVNgG/zqarEp5qf/6FDHzF2PH+LnP
         FxLGiEhsg9kYzabYcLsxzw0R+P4hma5Vkuc3uRM7R3yQ6SQ/v9v1pGbCwHH05R60HhHD
         tk6dwurs3Ypfei+LOQgNmpiMRj8AM8JpaDx0sc/LpcfNhekRqtPNmxDO5wAinRsLQtfd
         RuXasnAS4kmz/rwsgyHk2wj0v41oIMSzFQhR2/SRK7oHC8s+Q/zMs5aScMoFHN31BBiW
         htrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=lRjgyLP7U07TxhN2ElaeOZQwUxK6vKhYMw/dxP0O/sE=;
        fh=jxAcxfyXlXJVJajE4jbOEjTTlH381URFybb8ns9p0qo=;
        b=Ey5+4X/0eYAioCQHOJSemrbXQJcVQrncpystZZCkHceDBrz7SiMc8JKWHtMT/kyvQS
         +9wOt1C9wzAW1RQDPC9vIkxtH+gN+YSygN8WDz6yabSO9vVFE202GMWk3a6yjrOWkC5j
         dZYfTfGP+kBjZzp5YvVzHomLbQ/0XRMuq/ZTra0fmdnPDvKz7MXNsSEp+rhr063pZdbT
         V2PMihIPt2B7v7kyEFKinPgYwDfgvaCa5n/Ssr6KlPZztMQn63oKvhvoRp7WXvRqO0hi
         hAi8FmJHlgIMJj+DfJyq5B0s6XxPkQVoINi4xW7i/hfZkNaNVv3iQ4Rb1C7cTtPiYO0Q
         LPBw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=s7GjinpF;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.177 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708037679; x=1708642479; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lRjgyLP7U07TxhN2ElaeOZQwUxK6vKhYMw/dxP0O/sE=;
        b=lqEbIz62PX/ZK2HcGzqXQCNYB43/B80HYlmuvFSAp29MhhTK3slmPiyQ7K52XwGqgW
         S+DLTBiObcv4eM+Ig4NaeUnfLZ/KVTMI4uZoCyaIilMkCvGG5Om5TxynCPg+InVUwdcj
         XumKKAalvHpSEKEvBYzuOzx/UtVjVtdt+TQfKBZ9xOggkUny9BWYRT12MvYrFUBH9u77
         p7+NMgz4eD4ZdOZhWn/E5Uf6d5ywuU4deD9Msf3R+NAjWPZ6Op3tICAulvTj489QOn8r
         N/l6zyfvp9OEylFg2WWOHwvUq4tLTy+T/gnQzSHlGWLYqzo35JSSkMGW0E77QtwsJYR+
         zSqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708037679; x=1708642479;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lRjgyLP7U07TxhN2ElaeOZQwUxK6vKhYMw/dxP0O/sE=;
        b=ekMYSNrCCj1ggNYKX4WbsCMpQmvrstgsxbl4fqkM+twPMPr2XFk0ghQrkUeqqxBSTb
         vivwS4s1fBxOKF7H9dBlmMjNeS5XT4E4Qwdr+t//Gw8mjDq/juj3nf3PlUTXfg/fOdlC
         PZ/k+2c6HqXl8Dy3NpBsR13E8OwjRKQIh/PtDuZbjBYt+aRzS4ccG83i7ApjP8ER6hfN
         aFhm8tzc4H+Jf9cmoh92uFsurCXJy1Ha6EqtdvEjYvexzGFQmK8X8mKEpMmwRb36/UB0
         NLtN2qzY1N14ZulJspzKqkF1eCe+NLfV7Atz7fz4UZetl8RoI+nE5rL58B6eLbr5m5W8
         AEgg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVnDeaui7FZpidP2tTYle5ZEwnzMxfyF877ccWGIIHMYa8y2/Uo3HjynQMEUqh6uPVidbsxCOh5bzBBSibv3GISxlCd3Qei/A==
X-Gm-Message-State: AOJu0Yzz02Po5HWdr2OExkkJ4vFbC6KuqfGqWp1hqtKRQIiUly+c98Jb
	Cy1AjpbKrxv0mnpwcCnG+GD6iCRFNiaTWOyHmJh4wDksMQ1NQBrN
X-Google-Smtp-Source: AGHT+IGuAPw8mMB2lneNJd0IN1RwA9wOmwm7VXxaR7AuH5s0IMA9S7o5Y176y/3NA18e4ysz+qJGOg==
X-Received: by 2002:a05:600c:45c4:b0:40f:d14a:624a with SMTP id s4-20020a05600c45c400b0040fd14a624amr2287315wmo.18.1708037678797;
        Thu, 15 Feb 2024 14:54:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3d86:b0:411:e5d1:5f2a with SMTP id
 bi6-20020a05600c3d8600b00411e5d15f2als105376wmb.1.-pod-prod-03-eu; Thu, 15
 Feb 2024 14:54:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWJW+0wCKEQKR8CP51rhhYYq89dln6B92yCCKt9zpMoeN7T2ACsKsf92hydDoaamzSqBlbi3f+KOZcUcWNEyUueHfomtPcNb0Gl2A==
X-Received: by 2002:adf:f8cc:0:b0:33c:e2ff:953f with SMTP id f12-20020adff8cc000000b0033ce2ff953fmr2320978wrq.24.1708037676935;
        Thu, 15 Feb 2024 14:54:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708037676; cv=none;
        d=google.com; s=arc-20160816;
        b=nVkX/eZsFOhmmDGX4NuPzJW3fvaNZALf37ZiIaf+aMtZiX6veWXmrpxF2OvsDfMi4b
         69e7qtGVbuXRGHclUT7Tdi9Rk6jnbe+J/dpmS9/VF4hNA/fptI963Oj15Qf5VqwjzgE7
         U0Id8smn8ThKMgGDRJi+4TBxGG+ATbWgBwKcJ4YSu+YlTjd4cpF58oUQrD4xy+UgYD38
         Tll7CyiS/PMpe7Rc+IrIYyprcD7pB03wb6Ef0Nw6+J/0tPP8En1YxKl32mPXGvsuRede
         or2l+4/lnJ9+aDpOhgB5dd5pn+2o9jq6F0sA9FeqGbBOPcmefeqoxywB0tEa0Zm5dRsB
         W0Iw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=ZDSi9l3t5jb4xqm42oA6b90TgSdD5o5/qEQqj726Xko=;
        fh=+SL4WG84YqU46LFMZ8SzXTiC3jZabKWCyPkn0DT7bok=;
        b=qT2jzaK7ggq5eKfjFbye4XJ32gGgQFhp48zbp5glAq+S175Z+iGXyMEmtf5qiWY5VA
         Ksyh4YS6hQR6w4dYi4aIquG2cfmHT38k2kfTeLL0E2yBtvKN4fXk8ITWw+tzcUOLUa5w
         IySet0+JGpnNmD7Nu+Ryb0EhCnL+NRXItgJIxOTJbt7rZYtuRrUGUraO1g6MV9XPADfM
         djmKcMCkO+MJkqs00nn9WNqx56jnVz8nO2ma6g3HjYSgV+mGClUYo47YmijKf3LsLQL+
         3rGs61NXSzMFoYYNZTEEM4orbFfPsLlHHYrNpL5qsmi7Hy8t2M6fCvTMOiv4GbMasU7H
         RXPQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=s7GjinpF;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.177 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-177.mta1.migadu.com (out-177.mta1.migadu.com. [95.215.58.177])
        by gmr-mx.google.com with ESMTPS id m30-20020a05600c3b1e00b0041029861837si13465wms.0.2024.02.15.14.54.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Feb 2024 14:54:36 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.177 as permitted sender) client-ip=95.215.58.177;
Date: Thu, 15 Feb 2024 17:54:25 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Michal Hocko <mhocko@suse.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, 
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org, hannes@cmpxchg.org, 
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net, willy@infradead.org, 
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, 
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, 
	peterx@redhat.com, david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, 
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, hughd@google.com, 
	andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com, 
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, 
	cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, minchan@google.com, 
	kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, linux-modules@vger.kernel.org, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in show_mem()
Message-ID: <ojym6woqflzp6qarjgfubzq6wjgcju4cv4t3kfpfk77xhnxt3t@xmuarv3rdqsq>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-32-surenb@google.com>
 <Zc3X8XlnrZmh2mgN@tiehlicka>
 <CAJuCfpHc2ee_V6SGAc_31O_ikjGGNivhdSG+2XNcc9vVmzO-9g@mail.gmail.com>
 <Zc4_i_ED6qjGDmhR@tiehlicka>
 <CAJuCfpHq3N0h6dGieHxD6Au+qs=iKAifFrHAMxTsHTcDrOwSQA@mail.gmail.com>
 <ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
 <320cd134-b767-4f29-869b-d219793ba8a1@suse.cz>
 <efxe67vo32epvmyzplmpd344nw2wf37azicpfhvkt3zz4aujm3@n27pl5j5zahj>
 <Zc6ILbveSQvDtayj@tiehlicka>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Zc6ILbveSQvDtayj@tiehlicka>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=s7GjinpF;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.177 as
 permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Thu, Feb 15, 2024 at 10:54:53PM +0100, Michal Hocko wrote:
> On Thu 15-02-24 15:33:30, Kent Overstreet wrote:
> > If we want this report to be 100% reliable, then yes the preallocated
> > buffer makes sense - but I don't think 100% makes sense here; I think we
> > can accept ~99% and give back that 4k.
> 
> Think about that from the memory reserves consumers. The atomic reserve
> is a scarse resource and now you want to use it for debugging purposes
> for which you could have preallocated.

_Memory_ is a finite resource that we shouldn't be using unnecessarily. 

We don't need this for the entire time we're under memory pressure; just
the short duration it takes to generate the report, then it's back
available for other users.

You would have us dedicate 4k, from system bootup, that can never be
used by other users.

Again: this makes no sense. The whole point of having watermarks and
shared reserves is so that every codepath doesn't have to have its own
dedicated, private reserve, so that we can make better use of a shared
finite resource.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ojym6woqflzp6qarjgfubzq6wjgcju4cv4t3kfpfk77xhnxt3t%40xmuarv3rdqsq.
