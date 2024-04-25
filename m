Return-Path: <kasan-dev+bncBCF5XGNWYQBRBLPQVKYQMGQEMP2K6BQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C1BB8B2967
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Apr 2024 22:08:15 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-5aa338a43c8sf1638075eaf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Apr 2024 13:08:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1714075694; cv=pass;
        d=google.com; s=arc-20160816;
        b=DGj8jxqzBfZz043s0/0dzWXFqLYpV8Hp2B++Cs2HSXqOuwO1tNMQw1tEreB/jxRDAN
         YIdNwg+26ZaWD4ODsFeHY4JAqr4NYWclhPS1SDwduIoeiHDw5RyD/QKCXZtynykcoJUP
         6QSgYHGpOefPf2MZ1b+3cj2++VB24bv0z4/GLL2CQU1b7Y7paAQkke1RyZe4PrrxJJSj
         sbSrs6WHxFBFNOum3NOVJv1+7RicXfiyMq9mwsCURi1ZWoHY9ktpH2+CAP/pbkicfFax
         vfcjok0vMKKNh4gkiDgDp+sgWzC2/FB6iTy5KZ2aU3LUEK9I41jskWJRbmJstD6WNICi
         8AgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=zJDL+h1M11CGowWhpHnqgAbLgm6hWrAw3pwte43MZPg=;
        fh=qDMugMYzx91+o4s/jzXAhCkukS8befDMSsOU/pc01m0=;
        b=TB5DsgWv+kbXDviBARaI6QfZCkrR/vZH8gCwzLjH8g2OcBwGG1wrzO4xaEtFrVhyyl
         vlgdN5afjok+wXZJhSwoXWNiQh7m49AN06NYBxo/cFSJSWHH2vTGpxLKjJB2XNK4aM5M
         zQFTlaYZnYCm3fPlZL+vpG2FgIWMgA2h5I2Gg42bL22ZVd/gAhWMkhAs5qsSFNTYjRtI
         pxqG3tdU4T0ErpiNkpmKL9HJZ0u6g3Ke5ga2oVK03A8gM01JJdS13yMIc7fba5nBdAzn
         scTyuVQIHFYipxqBC5jbTKug+5VYF9qkoXALAnCpAVk69cDuesPwaBpnE+JgOHu3olrb
         MEZg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Ec9BEJ0n;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1714075694; x=1714680494; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zJDL+h1M11CGowWhpHnqgAbLgm6hWrAw3pwte43MZPg=;
        b=FHxJ5IWkqHJA5F6J/4uClhqhLJO7ImVMc362K3wRZAtRumV5A2HOD5lZZSIkKWgzW9
         bWN6eZok4B0zinDmLu7Nyaw7Te3Gq/OtfbDLe/frrVU7dJLIAmmt21WvBsbl562KZvp9
         RYWGWefI/gLTtrqXhpGg3W/efLvp48txYwIFMnN14iN1QqzgL8HvDF9ukPP4psLDPCs4
         41ZIBk6u/WZRfySBq/tXmOELLxyPAN84nx4NooUSNiGGbXeF/kbqWYTAcIzaFy0k+kGS
         ng4Sew5T6rrQBqHCqesumHjEi1ZvwQDiIoPZ9HuTCaOlXHTMg84m45QHGlhNvxyCKDo0
         kh/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1714075694; x=1714680494;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zJDL+h1M11CGowWhpHnqgAbLgm6hWrAw3pwte43MZPg=;
        b=ERvqHebH5v686oST9MflJIo0lWdv5Ywn6eGNf7h0C/PSd/AsdHz0xfsjMlZQXD44hF
         //AGOSS50rnZ+joOxJgH4gROmCXVkE6w38i5d/RetDQsB4XuQpbJdPvwgAy1DhNeka26
         PqQQ49AxuRFmViP7YeeGAO4Z/bqcDWnKgLgTbMX72zRoxbfbhsYgTDsZdoHvxccp5dFG
         8WT3xjjUF4mwZF6Z5QZLqyFi1J+z33d9CeqRYofBcUVTCeUmFVvs57jKS4z2qq42/MsH
         ofmBwDWiP5bykB8+Eu2Zjl+WxgtsJ4ek8SN3ZixAcfIwzTLv3OKKbxkP+gLe6phCz+2O
         Wyhw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV7qgkQ+osHspIaa0t/GKgFXHZm3PlgYptucaPuCyvG1Ozk6irQC6rfHNWvMEHszlRV7lkhZUQ5LfeQLmzYYO7ZKti/4T4iWg==
X-Gm-Message-State: AOJu0Yy4rjOcuEvwRrUPnBryh3Kp/xq0kAAl4uBJ5TTb3edhcSOwqLSG
	Pjgyi5E/syUgGwOsF9DYX1HMCKtKHLD3KgYuFkBbcr6OBjqwYN15
X-Google-Smtp-Source: AGHT+IG4+sxfl/e9taNoONs+HpNUtEDxKal4WzQ9ksv4ed59bEplfpUSjIKhNs+SJjAQi6B1yd3/UA==
X-Received: by 2002:a4a:347:0:b0:5ac:9f40:16a with SMTP id 68-20020a4a0347000000b005ac9f40016amr863212ooi.5.1714075693654;
        Thu, 25 Apr 2024 13:08:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:4e87:0:b0:5ae:1f6c:8982 with SMTP id 006d021491bc7-5af5d35e513ls1283304eaf.1.-pod-prod-06-us;
 Thu, 25 Apr 2024 13:08:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXV8s/d9FjvdJcLwGlnzhZ4qAJvLqDvt9wTf7zh9zuz7PQAqmMgqUvIWi6oVqlUBTSiT+iJGxqthU2q38dxDtEwkG2WzT/1nwYCAA==
X-Received: by 2002:a05:6808:1528:b0:3c7:dfb:a295 with SMTP id u40-20020a056808152800b003c70dfba295mr849701oiw.55.1714075692919;
        Thu, 25 Apr 2024 13:08:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1714075692; cv=none;
        d=google.com; s=arc-20160816;
        b=qOUIF/6ej5U8zizAByhTIwWLX+Mk0yz9CfbCfN4MRnLRkAxZ86bAZ/NhIdWL0oxpoX
         eWD69KBM9wJcrwoKHmQHOJXnZ3X3AOwGiFigz3yoBHTNW7f+u1oq5n8V9mAa59S8VTuB
         fTaB4uah/5ebcXeyGw8Baj4WVWfRKWLEnlpo9KtX/6SaaWF/KNOtCPDJb9/qW4Z1F+lx
         JT3BKaMp4mns4YGCiCGifB2RIWWO1WWP+2+oSGRTl2cLarjVowDN/u4/IoPsK/KS0Jmh
         8JkGqAx6AyDiKR76KhhaGC3iKePlZSOESX1Thze6H0Ya2pHuXylgEZ0hCsYmQ1/SndQM
         qDXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ekH2ncVU5TU90wC0+JU7SiT8D9UwcwiJNzKzOJmDUPE=;
        fh=m+9bs0m/8+2LsD8XHm4ibagMmNzxU6b59s35dcjUETY=;
        b=xXD32ND9ttcJh72LB0wzY74lDIRdqwGjcCUGYsQsYVkjr7elsTX+5lMOZOu2nylpxY
         n17JQ0BeAy/sv9bslzMUqzyJALsgCvWt3yjNxSMPz7YtRfySdgYN1TPMk3ZsD/yqnUBp
         Hyfy+yrFM8Aa6A2Jc3Z+fNTH6ym5RDTok4Fu3yZs9DB1JZmbIpL6CG0SJ4dMs3LuEdfx
         1E9OnSsWaUEAu8kFofEIHlbDgzhqhXZvmvAJPKIODHLXByaTS6h/uj5XuP7kZpAdRuTi
         +qyB5goSpaEFo2unHowfqkY5cfSI9aLCJ+pvTkOVwzxvEIMzfx+zEoGV0HrHnJkBXPWp
         ysZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Ec9BEJ0n;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x433.google.com (mail-pf1-x433.google.com. [2607:f8b0:4864:20::433])
        by gmr-mx.google.com with ESMTPS id n13-20020a05680803ad00b003c854953770si74246oie.1.2024.04.25.13.08.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Apr 2024 13:08:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::433 as permitted sender) client-ip=2607:f8b0:4864:20::433;
Received: by mail-pf1-x433.google.com with SMTP id d2e1a72fcca58-6edc61d0ff6so1454304b3a.2
        for <kasan-dev@googlegroups.com>; Thu, 25 Apr 2024 13:08:12 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXoM6uYoK9710LGzb5gx9gFkLLlPeJ7Eug4E1kIcyTKZPmKvYwt11MOkBoIysri9JNCceGEutu+SV8aiUXNWxa28eC+r+/H26r9hA==
X-Received: by 2002:a17:90a:bb96:b0:2ad:e74a:f500 with SMTP id v22-20020a17090abb9600b002ade74af500mr621422pjr.27.1714075692101;
        Thu, 25 Apr 2024 13:08:12 -0700 (PDT)
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id n4-20020a17090aab8400b002af41bd563esm3357299pjq.33.2024.04.25.13.08.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 25 Apr 2024 13:08:11 -0700 (PDT)
Date: Thu, 25 Apr 2024 13:08:10 -0700
From: Kees Cook <keescook@chromium.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, penguin-kernel@i-love.sakura.ne.jp,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org,
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org,
	jhubbard@nvidia.com, tj@kernel.org, muchun.song@linux.dev,
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, ndesaulniers@google.com,
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com,
	ytcoode@gmail.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
	glider@google.com, elver@google.com, dvyukov@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com,
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
	kernel-team@android.com, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-mm@kvack.org, linux-modules@vger.kernel.org,
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v6 00/37] Memory allocation profiling
Message-ID: <202404251307.FD73DE1@keescook>
References: <20240321163705.3067592-1-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=Ec9BEJ0n;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::433
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Thu, Mar 21, 2024 at 09:36:22AM -0700, Suren Baghdasaryan wrote:
> Overview:
> Low overhead [1] per-callsite memory allocation profiling. Not just for
> debug kernels, overhead low enough to be deployed in production.

A bit late to actually _running_ this code, but I remain a fan:

Tested-by: Kees Cook <keescook@chromium.org>

I have a little tweak patch I'll send out too...

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202404251307.FD73DE1%40keescook.
