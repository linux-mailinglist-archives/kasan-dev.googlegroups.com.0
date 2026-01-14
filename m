Return-Path: <kasan-dev+bncBCKLNNXAXYFBBR7CT3FQMGQEVPKCEOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 50720D1F9DD
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Jan 2026 16:07:53 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-477563a0c75sf53838665e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Jan 2026 07:07:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768403272; cv=pass;
        d=google.com; s=arc-20240605;
        b=MRybKizF19LBVNn0+8Gjrc5FZP59Rw8IuLkrxe8zl6sxTZ7GbV9Xs4PJZPBPVo9XPb
         LhBGN7fGJRzOhtFviWbA3Q68ZnxSrLlYn5Jw7MU69z5Vgi7uzK8KBgFH2wOENU7my8rL
         ctMNGo+4TU+nxcyGRXvVrq18JPP+1cBeOsCZ7pH1ysylBJBF+B41SNLy59niygatdSZz
         H344O97rXvYSXk/SUUTpCQY4aFMJwo5whDfXqlaNM7RtASp2AAPrljqLaFUN+4nsu2NM
         B0obfWgidEj4SkIRpCtTk8fPNFZyjxLLVykOTHekwXpbTsvdodaw+ahDF0IMUwqlJ96p
         ro0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=sfvRyE+2pN3raH6uWEW70DVLxIDRavxhkdpTqweFvow=;
        fh=y5g+tGZUFBT5bA3/m5wIWxyL2KCqYTnSq3h3tpKVNtQ=;
        b=V61Ydtwq5W733KfH9gMRM8N81iwGMeSKw1wnJWdZiu209Hcc8YtHRoUpEcGqQ9xRDO
         ObChMCE3AG20c7LeIZm7hP5QyFZtkdkQVel98tOqaHEK2zZ0AMNP55pXIJARJ5NNUcab
         aHczB1nrkEmgjpuSeBDYfMZv+viUFA3Nz2pn/B9usw974w80SBu1ybsgLpUceJN2iabC
         Z2+al8nvWcMDudXuQO1Zv2QkepOkIuRlrHCxbQIVQdoDl+XCAYPgaATgSzwDMKGccjpw
         1F+uhCJ92U78kOnteob5aLSHSjbMUuyxJNppDyoXA4fY5f5litmaScRvuRobaK6W+2nt
         dCSA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=DpI+2DhX;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768403272; x=1769008072; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=sfvRyE+2pN3raH6uWEW70DVLxIDRavxhkdpTqweFvow=;
        b=HCdckqtqICHOo5AfMUpptYIKcS7rxWwazHvTc94HxUmU/zi2EZlcIfJVA99cLu47pJ
         fex0/XOVqvNbM8TB5KZy+jmXypFqWYXt7BuvVxi/UUE3fa1MGZnClbet+UTu/3s0SWIt
         SuA5N/HMtF1uE0X5hHWMgKy7XW2/dr3xReOvYJs56/kNgJ2kPO9h1nnyeKnYDfXI1PHt
         2OZrbXfs1JmLKsI23yPwHqdD/zut4R1BM+e5I+r6K8zqvN1TNWmxpDdOCVcJsvjN487m
         zat7amSwKNxJedlYTZl055Qc4jqhmu3SRTFlEvTJeY6SWRNboLa7fIIZsMbk+E0nnfQ4
         HQpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768403272; x=1769008072;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=sfvRyE+2pN3raH6uWEW70DVLxIDRavxhkdpTqweFvow=;
        b=sjthp1DPu+qMr9AIiSEvAPyODXS+aK/dl+P1QIq2RwVGLkl9wTADutZ2nwjNUCzw/r
         DTo7Ev5GH0Inua06hc+9s9mhy5BkCBnOD7QtywBat44/xwgGnm4DYQExkYpafjfa3qeH
         PxPNBnKgtwheJSvBJthGEfisFoTxl8xQj+/bBArz3/f889S8QOV6d7t3shxJC7cXII0T
         HsYFPDszU8t9zmevg2u7JiXpzmK4FeaUd0fKgtez51k00XNEm9XtQCMS8swytSdrrBwF
         h275Z6ObNdZCCEHgST5lEOWr+l4jzUxMbiShfW1pHLDnxxOTSAcLfCa+oeUjB+MZPSxF
         lmLA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV9Vectd8+4VquazzPjZ9+q3Qsonh4j5YlvJn1sgpaneqsavBCT5TrQMn81lnYq6Yx8/GrLAA==@lfdr.de
X-Gm-Message-State: AOJu0YyOIZuqrWeFItNVYoSDSqbJX4K/R4TBbAkGf+2MOPhpNRi+dojd
	it5VzxaoEJs63/50+ryTX2dr1U1fJ79PfNf+WmD3vWVv+h+YVIAQk4Ve
X-Received: by 2002:a05:600c:83c3:b0:479:2651:3f9c with SMTP id 5b1f17b1804b1-47ee32fd063mr34150685e9.14.1768403272011;
        Wed, 14 Jan 2026 07:07:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+G5P4Xd2zW/JWm03EUnfb4d6CpygboCdKEvOenRyZUSSA=="
Received: by 2002:a05:600c:4443:b0:477:a036:8e82 with SMTP id
 5b1f17b1804b1-47d7eaa4893ls57847285e9.0.-pod-prod-08-eu; Wed, 14 Jan 2026
 07:07:49 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXOKnDwhHLxO0QK/47lcdY99gonBDeGg4htFqoJp7jJqM2VMWQ+bUeXY28e/pzybPS6Rf6b62KPfV8=@googlegroups.com
X-Received: by 2002:a05:600c:3555:b0:47b:e2a9:2bd7 with SMTP id 5b1f17b1804b1-47ee3363c12mr40727695e9.19.1768403269509;
        Wed, 14 Jan 2026 07:07:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768403269; cv=none;
        d=google.com; s=arc-20240605;
        b=FKa6F4D40+8SoeuYeZi14twxTqg1LEvjjehPokE3Qxym+XPHWWefBPwpDWarTEou3O
         /kgZBsIAyGnwbUm0KC40TjjqSiUcPitRkTWvjfGC/2OY3GBPVAyoj5DZaRXQeiAi6HmS
         LSUixmwTdfgwqRTpg7JaNjhrvxrZkE2pjacC/aLcC1D/4Vjh5CRl0WQ/7b2ER/TFrD3s
         w5BTzpTJ9Cn7JeYzpDS1sYxXdL7vNKprJRq8Co6MSxp8eFSY1QSYXPJuFzvBmYKWsnZV
         lDOqGu8A9mhkz4BcHjJxKg/SQjqLdBUFOXrU/2z992zzwtknLmtmP66WInGLiBWbeHPw
         stlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=4C72mCKj6g75hWi4SDABu63k1LKvcFbsA+RvmMJke0I=;
        fh=L18ASGPvReSUENzZI9E+DM8tpDblAElFJQwOUVMax9U=;
        b=BZvU6zlA9Do5BzxXeRKBCciT8d5fJeKBvMGoBLT+wxfI8dQiAlOvxm0iKkW4YWodeu
         LYvejVr065NsZSrli2ScgcXfOOPGzJqVZU6BQKqL/Yhu5GtvRcpgOET/pKo0b8+FZ2fY
         v0jo9FHfc7mmys273l4WFWB3f/8MIp5/1bt5oOG8zKAfDwAA/sKcUWTtkS1mowuq6Qu+
         Gp+Ty+u7APGIw/cmlFj2hhZx2eAMPQ489DdXFigaE6f4d8PrO6Pj3oYKOERUh2QK/WL8
         dYAv4d8htVA1SsO7MNuaUlzJLTuJEXUjeGpxcvWSXxe0gIIlxrWOMm54/FvCyvKN5SlL
         CThA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=DpI+2DhX;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47ee0b488e1si306295e9.0.2026.01.14.07.07.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Jan 2026 07:07:49 -0800 (PST)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Date: Wed, 14 Jan 2026 16:07:47 +0100
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Alexei Starovoitov <alexei.starovoitov@gmail.com>,
	Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>,
	Christoph Lameter <cl@gentwo.org>,
	David Rientjes <rientjes@google.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hao Li <hao.li@linux.dev>,
	Andrew Morton <akpm@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Suren Baghdasaryan <surenb@google.com>,
	Alexei Starovoitov <ast@kernel.org>, linux-mm <linux-mm@kvack.org>,
	LKML <linux-kernel@vger.kernel.org>, linux-rt-devel@lists.linux.dev,
	bpf <bpf@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH RFC v2 06/20] slab: make percpu sheaves compatible with
 kmalloc_nolock()/kfree_nolock()
Message-ID: <20260114150747.ziWhVVQM@linutronix.de>
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
 <20260112-sheaves-for-all-v2-6-98225cfb50cf@suse.cz>
 <20260113183604.ykHFYvV2@linutronix.de>
 <CAADnVQK0Y2ha--EndLUfk_7n8na9CfnTpvqPMYbH07+MTJ9UpA@mail.gmail.com>
 <596a5461-eb50-40e5-88ca-d5dbe1fc6a67@suse.cz>
 <d8d25eb3-63c4-4449-ae9c-a7e4f207a2bc@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <d8d25eb3-63c4-4449-ae9c-a7e4f207a2bc@suse.cz>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=DpI+2DhX;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On 2026-01-14 15:05:34 [+0100], Vlastimil Babka wrote:
> > Yes IIRC Hao Li pointed that out before. We'll be able to remove that
> > !preemptible() check that we area about to add by the patch above.
> > 
> > But I'm not sure we can remove (or "not put back") the "in_nmi() ||
> > in_hardirq()" too, because as you said it was added with different reasoning
> > initially?
> 
> Ah right, it was "copied" from alloc_frozen_pages_nolock_noprof() where it's
> explained more, and AFAICS will be still applicable with sheaves. We should
> add a comment to kmalloc_nolock() referring to the
> alloc_frozen_pages_nolock_noprof() comment...

Right. This looks halfway what I remember. And this was works in atomic
context on RT because of rmqueue_pcplist()/ pcp_spin_trylock() usage.

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260114150747.ziWhVVQM%40linutronix.de.
