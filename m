Return-Path: <kasan-dev+bncBCX55RF23MIRBUMC3GXAMGQE5XQUYMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id D845985E600
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 19:30:42 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-2d243ef274esf29405351fa.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 10:30:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708540242; cv=pass;
        d=google.com; s=arc-20160816;
        b=bnyFA8QNGa4SpGJkizKiU497O0ibxhN1xv3d6dHdvQ2kMibnuunrwx0D1jiBC95zmu
         hJL2fS54ZFnpxd4pxkX9hu0C2Thrr4S68glp7jTr9T5aWq2IWArROSC4ddXzdQyKY5is
         piZO44RWEAhMCZmqvEO0CCYtg+fdzigPQQiKHcANE2+Orc+B1bjtkG2RPWlbGELYk1Rp
         M7+F1JvMJ4/h8tlafL3/D5miig/pzVM+KsamlJaoGWvUzpcOR/DJEyAyW2PGg/Ec+eoQ
         Xu4CdkqOGl7NUNSyblL6MHek10g3fxSMSQ7NUNXMWTazTu5f3w6CEr4P5d/pB+Zze6F+
         BkFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=HZ25eko7nYBiSVfsImMbNkADQP8uIpgr6RbDlH2jnhs=;
        fh=AmXcwANn/CzojLY0oSmC+IQo2MUpbgB5/gy4RHCSol0=;
        b=x9XusN5I4mA1As/hgZjxEcVvJFxKsZsQZUoJutEmuWnnMymxzsBQoT9iLLpxnRMXyK
         66VA+ZEuuf6+o2Tx4slgzbg/eyojWpEh+nvs8KfE69Hb8cA9yJiTjNgojWZc6uOBS3li
         NhWrCIhhAtw6irqZplBoFXtMhITcnJg8CpI0hmXk+bCHaxdHvFNuVv+TKnZLbBPq6nC/
         MwmDJzKwuhMinWbqEv8cPJJqP5jO9mXQSxLrL6Wox5U/q9aSKUAunT3UG6tYfC/vXKpj
         kIzWXpERE1G+SJ5Y3zYW80QZTEleNODxKIJFtNRMRqQ4xylSMNTwhOmuKlrx5ZPvIZsq
         Cv/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=sbJ6zd2J;
       spf=pass (google.com: domain of roman.gushchin@linux.dev designates 2001:41d0:1004:224b::b8 as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708540242; x=1709145042; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HZ25eko7nYBiSVfsImMbNkADQP8uIpgr6RbDlH2jnhs=;
        b=UE7DDyhSkfG9vl+we+6xyAZ/dAG+D2OcZEFLbxrQZgdIBLhh8eyM4ipMR3liN3rvIk
         4QkfBCnLw+wfY2EoAEoLFqy1pmbREHwrkwWxMC8uV4bopVn+ZURrrh59ixgTUApekNDF
         q/37jwpYD4E7NbxLaW+xg3wZVdVNLy0osJ/lU2Mu6vycmDCviJzdtKlZcQWPHYW5sTVy
         NI3+pVvw1m9hbo9zUwhFQblh24HfZxKgQx1JUs/wicKe4FfrAT/J3/Iw9ec0DVgV6OuK
         nA30UKsUf8n7Lgq1y3a7WYNRn6j+MVDl0yg+xGafZD5P2ZZu5S7APU7ZU4Kjj3lc0eQc
         LVTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708540242; x=1709145042;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HZ25eko7nYBiSVfsImMbNkADQP8uIpgr6RbDlH2jnhs=;
        b=nNvfgupefF6fo3LGVOiQYz59USiQgXv9FQ8slDZoWiwZer6fHEv+pmnGojRFiaaKae
         tPfOV3dG8KJnzA/uCWuhIhs+xtWGDsMg/6Txkys9TQ88iI/JjYnAeZHzRIfP+TcmEQ2F
         qVck4N7xB1rPFBdMCrov93ICZ+dRxU4Qi/oUzpCIfCLy+TyyC+0OBODCCYDofoXDb/Ti
         M8jVjx/kJpNcHJgq8Uf6sfx0RBrZztUrI98Lv3T5Cdh0v54jwcs/g7TssWCJsl7ZlgxS
         SAq8DgrXMU5gsWQZcD/g0KG3fbeMb9eIPYDA2EPZuwdguTcQsjOXOTQJeLhKTe7re+dx
         ipZQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWyIvdY2d0rVVDwLXDwFU3FjAN/J3+LXeShc/aCa6Eq6vtaOMhXSmeoi3WVKBlFvry9hoGC7/1Gcl0NNmbV6VxIwLPhw57vYw==
X-Gm-Message-State: AOJu0Yyw+7DS0la2gU09lY49+hVoCDHnNFPio0npsh7N6LzKd5ekZCy9
	82Va3SLs3l5AjPVXoaDnMIezeCqJ4EDeaNmXVw5Xq7ym+Pv/ab2G
X-Google-Smtp-Source: AGHT+IHgJrz94z74d2HQosW6uy3f22i9DeGyoPRhhBGkF/3gW8RbSwSM9TjqRrowctbfOy98sG8txw==
X-Received: by 2002:a05:6512:4027:b0:512:a52f:468a with SMTP id br39-20020a056512402700b00512a52f468amr10132523lfb.46.1708540241628;
        Wed, 21 Feb 2024 10:30:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d18:b0:512:c39e:3a7c with SMTP id
 d24-20020a0565123d1800b00512c39e3a7cls568703lfv.0.-pod-prod-08-eu; Wed, 21
 Feb 2024 10:30:40 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWT0j+4B76PZzl3+4W8W9rxbAnh8QhOQmePZT2wIgTM++k2oU5TgKxNnwyeM8r931T6ppybQNbr5PzqoXev8vp5w4iWWBTMiXmicw==
X-Received: by 2002:a05:6512:a8c:b0:512:bf58:f446 with SMTP id m12-20020a0565120a8c00b00512bf58f446mr5214818lfu.54.1708540239665;
        Wed, 21 Feb 2024 10:30:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708540239; cv=none;
        d=google.com; s=arc-20160816;
        b=kIHAfyfRUGHhYNz/SWdi6/fvmHhiqdCFayX6tVhfLrrDIocK5+k5s7wKlz3dYBnKdW
         mPpIkkJBQItoFrjkb6aUILVkruvG79FrG35ti9jLDue9njZUmAb+l5AXu64XHB4eFHj1
         ToNTJIGPRBHleevICLb8rDrmtMWOpSvoafrUwAL8++0mXnMLq6Az/+fndZwnDz+LUuaR
         IkAZVx8p/g8YUPdNbnONOl7yDA4hCQirtghFkTnCcJ7ahFZ4xZnGgNBHQAmndIqw81NI
         nAFrtBIiNY2zcTb5SP+w0AByxazYlZgHh783fdomAaj/vmd5Oo4s7FelDIxIFsEMm6kY
         i6yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=FekxhxYh2M8PuEvR0875ALSaW6smsNFC8mdylkThqb8=;
        fh=Phzt3hna3AwNVRzWTqP2m/PPoxytiMYlWrMZPINGtMo=;
        b=LU5vNNtpVILuSQxs0P+bFpMWmRs4c+zEQzVZzTlaXkQg/9YXffOiiglSPD15sgkj7o
         6BKe7BUNaZ6WD6SsweKROipk+r1U3cJUT+6qlBCeh6W4p6KH+fcZM/hlDkHOib5zFgau
         hmFfTfTvssZ50UyA1X1m2liNaigglBsx71JmX0LRpJ58NEQwO4BbwAL6eYh2uurBOjNf
         8H7zOh9zNl1MGd1qrAFlO0lGrBCNP77IU+WZyPKeL2JdANMacEMjEChsa1Q85/mF+wO4
         gbgv5TzFjymVMAioGP1d+CY62mP9/a5mTJVmrHvaVmRyP5WODtpBul00Xn6uqM1JjVTR
         Z0MA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=sbJ6zd2J;
       spf=pass (google.com: domain of roman.gushchin@linux.dev designates 2001:41d0:1004:224b::b8 as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-184.mta0.migadu.com (out-184.mta0.migadu.com. [2001:41d0:1004:224b::b8])
        by gmr-mx.google.com with ESMTPS id g7-20020ac25387000000b005119e6adce0si507189lfh.11.2024.02.21.10.30.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Feb 2024 10:30:39 -0800 (PST)
Received-SPF: pass (google.com: domain of roman.gushchin@linux.dev designates 2001:41d0:1004:224b::b8 as permitted sender) client-ip=2001:41d0:1004:224b::b8;
Date: Wed, 21 Feb 2024 10:30:15 -0800
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Roman Gushchin <roman.gushchin@linux.dev>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Zheng Yejian <zhengyejian1@huawei.com>,
	Xiongwei Song <xiongwei.song@windriver.com>,
	Chengming Zhou <chengming.zhou@linux.dev>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	Steven Rostedt <rostedt@goodmis.org>
Subject: Re: [PATCH 1/3] mm, slab: deprecate SLAB_MEM_SPREAD flag
Message-ID: <ZdZBN_K8yJTVIbtC@P9FQF9L96D.corp.robot.car>
References: <20240220-slab-cleanup-flags-v1-0-e657e373944a@suse.cz>
 <20240220-slab-cleanup-flags-v1-1-e657e373944a@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240220-slab-cleanup-flags-v1-1-e657e373944a@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: roman.gushchin@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=sbJ6zd2J;       spf=pass
 (google.com: domain of roman.gushchin@linux.dev designates
 2001:41d0:1004:224b::b8 as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Tue, Feb 20, 2024 at 05:58:25PM +0100, Vlastimil Babka wrote:
0;95;0c> The SLAB_MEM_SPREAD flag used to be implemented in SLAB, which was
> removed.  SLUB instead relies on the page allocator's NUMA policies.
> Change the flag's value to 0 to free up the value it had, and mark it
> for full removal once all users are gone.
> 
> Reported-by: Steven Rostedt <rostedt@goodmis.org>
> Closes: https://lore.kernel.org/all/20240131172027.10f64405@gandalf.local.home/
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Reviewed-by: Roman Gushchin <roman.gushchin@linux.dev>

Do you plan to follow up with a patch series removing all usages?

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZdZBN_K8yJTVIbtC%40P9FQF9L96D.corp.robot.car.
