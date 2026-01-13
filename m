Return-Path: <kasan-dev+bncBCKLNNXAXYFBBGNBTLFQMGQELWEPFVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id E2202D1ADB7
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 19:36:10 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-59b6d228006sf7859220e87.0
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 10:36:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768329370; cv=pass;
        d=google.com; s=arc-20240605;
        b=YhsgLFC2GkvJvMSuudOGNbhU+Q/lqtImC1hBwHaPIhyniJZsx0jdyHL+/+RDWavJo0
         ew8ZOXEgACm6bBfuFipLmHG1qFkCkaqoDIMbK4z47kl7+oajggKFDUtH9YpWmOvW1ind
         lDX6/+oZKMTQDyHpVcwaQhhRg6W9VuiKjd3CxbyokDJnd0BEIoJ3uHjyzS/+0Z17akm6
         lZTbKtuKCfrOUIAw01ZKk1q8ie6SG0cEivmCd0MojfLFU1wZuHXnFkrRT8dC6erUzskF
         ufoUhdkCKrIIc0Q2o0F54Ikbx4M+A/WRijMt+C81dpGPWECo4BiposAh5NI86y7aqCrp
         0YIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=dtYFSXqav6eD0NZUh9W/YZHmtLRfGsKIqtJrCuO0xNY=;
        fh=F0mQu+A4tbgFt4M/X3gQqzCcHFUeDY6LpPj6qoB5kqY=;
        b=ldjXYl+B0BsY6h8a+QzQSgNcN7yAMeDrjx7EwIhaRlRhPI21hqji1XEeiyatRMJV9q
         W7FB+Zh+dS8e1GxvM+482PJ94Ohvi5gb1ZnOAGGJKks5VSk9IZdeTBwfduHrV0LclFc0
         Z7NMlOUqY/21kvophRh8EO3p+lmBdLcDuEJC4jyy2QVD3urQPPQvL9pThAEc8Qwm+DP6
         5og+S0nJoJMVq1Yx+S0c9K4ys7Hw7VA2qZnYcrwfH/yZLyoxNcVij3dQJiEI2OzbRMlH
         EPWAmGYoDB/MKs1q7DXDReNJt1WfUzaDAGsrECqKhctKQyTLGwvC+e1Ol0QLSxzURSwm
         Ekpg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=hFImr025;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768329370; x=1768934170; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dtYFSXqav6eD0NZUh9W/YZHmtLRfGsKIqtJrCuO0xNY=;
        b=GKeehx5wIPKDctLqhAOvv/1NnTAIcTp19bwIXCmDbX9nwMMnWzbHmq/85nZslv9FQc
         qMhVMsRThrwp37IUSFckS/KSIRW5+vRcWfXA1JCUgLDyhcqXLOUGp502puw8ojWtgNhp
         BBLQbxeQrx1T8SbyVhlR8xuetf7ZqAvhPkcuw+dKmZefTeVMGp7Fco5lTnwe6sYJ7PAF
         cPR83AOwEE3ZU6LwaYis53lHlgZvbnOJ7xgqlFvfajQSZ2lbp8ToyqbaXumvC0c75q7U
         QUEd2w4z8UGeKzUllAFMefPBs5vlltfUvuksHMBtyiIhg+CK1rzDyJdnYt/nkN1kzmYJ
         +4tg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768329370; x=1768934170;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dtYFSXqav6eD0NZUh9W/YZHmtLRfGsKIqtJrCuO0xNY=;
        b=W0gG1RAYqRTXxia8p2usgzhYWiplnbAk/kpcxFJkxwVgI5ew0A2I31KFhdoFpLcqmt
         g6bqUv/zweasgLv8lWUMjbTraYdaZerGe2ltjfh2QKID4d4wUYqAwtVkOlnn55KvmlLL
         IJJkxiursctsocg3kvoZHd+67OpYZu+PkVzpAJnPG5XJmjp+FpJOIMaVCostm7mfg0FU
         SE7JhF/6CxxU4koILaAO1bl6G+hUcGAyx9gIx6dJMxe3dbANe2LFvkQURUYnIV9+QcdD
         TaTG51JvtnO+++9jIANVB5QX2XEj/RlBYHXSFzATbIP8li97feVFPZY9oJYinOfD36n9
         Hz7A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXDtGCxQXFuATeK8rVf5D1+YYWGVpgbmcbsMfA7TLM5smZBGEStmfdSzVmp296cEBbrD0n7nA==@lfdr.de
X-Gm-Message-State: AOJu0YwkrpkjW8KrBmqi6IeV2fq8sy0EJ8wyLPHMqGs10SVI1oLi1Q76
	0ed3yVY0ur1hemlEM2ToK7QZ+vYQ5bhiFRA5vbKR4OkhoAvaMrtTCe93
X-Google-Smtp-Source: AGHT+IFmLhqOUAlrM6oOZ1Fj4p6MPfmQVumdJUVV+0S9siFebbXQBT9EThDwbAaEIqKFaRJalRD1RQ==
X-Received: by 2002:a05:6512:a83:b0:59a:1357:e449 with SMTP id 2adb3069b0e04-59b6f03a118mr7512218e87.42.1768329369837;
        Tue, 13 Jan 2026 10:36:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+F1yVr4zIf5JNgEA009kLPlgaDlosg/h0qhG6VMStTrxw=="
Received: by 2002:a05:651c:2544:20b0:37a:2d92:62ea with SMTP id
 38308e7fff4ca-382e91ae664ls8137421fa.0.-pod-prod-02-eu; Tue, 13 Jan 2026
 10:36:07 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVAZhzHcQsLFh0/razFQafZFbTY8Fj0ZDyhxjFZpjBOmk91nzsGHmjhrrS3MltsatTQVM6UKEEsQDo=@googlegroups.com
X-Received: by 2002:a05:6512:3182:b0:59b:809c:f660 with SMTP id 2adb3069b0e04-59b809cfc5amr4595331e87.47.1768329366727;
        Tue, 13 Jan 2026 10:36:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768329366; cv=none;
        d=google.com; s=arc-20240605;
        b=VdpzwX326Ly8kLx6+3fHmZKrPLWA7DbNjPi/LMlxn8sz5VVIHEfeNC6QvbsmVkvlGv
         fZyeoGfaV84o+kvT4Gc3U4rbJNv7TKlaKLR5GajHeJyc95D44dMxN3rZFVCn2+OfxP2s
         k2LDabLWnkG5dAXIeCyohAGev/e1PWqjJ2uXS7kNTm59d66XJC5oiiJnetilqRsel+YB
         CDgOIYtX0kY/t+SBUqasXw64mA07vBP6U8ZGHV0xqpaKUyRmMg2mqvf3yV8+xshlwEG7
         hzKdL8H5v1Dfbv5caVCUyxkMVp5mwAfW9C4MfAytnmNc44M8gH7tx865tpwIRKm57Ocn
         VtMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=pipRsFX69esF5KPLH4c9+I4B/dXZBlcjVkgFMV18ALI=;
        fh=wUqdArsOowPzOOLYMkqZLLq2j9vrsezoJ7O4ioDo4YA=;
        b=kET3BYseRV56p4tviV62xyCThfyNOSrYthECHST273Y6V+5WKHgO/XxsQUOAvUJd8Z
         5SAPgVdN3++Xbplbs0XdJAAoJkxMArpSjPmhXS0jHqlXhN5+E2u568DKBc7Kv4TZCgYQ
         6PEZr7X8luOiffm2Hr3wbC/pUkgeie9GkMXCG7Jh3Eo5Zl+NKUCMHtQT/1VGyDPlWq4y
         ldd+PJdgttEO8Ow0KUjNhxu5fBouTJuZDwnxJcLzioQlCtUNhTXzNxB+92/+o4NZ5OMd
         Hi/wZiQB+nkMslEnYK9KVTfn1REcTtNo65mbDkQmRWGWa6fsp9fM9OU6yuo+JHVoXGwk
         gRsA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=hFImr025;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38312397ff7si2592561fa.2.2026.01.13.10.36.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Jan 2026 10:36:06 -0800 (PST)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Tue, 13 Jan 2026 19:36:04 +0100
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>,
	Christoph Lameter <cl@gentwo.org>,
	David Rientjes <rientjes@google.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hao Li <hao.li@linux.dev>,
	Andrew Morton <akpm@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Suren Baghdasaryan <surenb@google.com>,
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
	bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH RFC v2 06/20] slab: make percpu sheaves compatible with
 kmalloc_nolock()/kfree_nolock()
Message-ID: <20260113183604.ykHFYvV2@linutronix.de>
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
 <20260112-sheaves-for-all-v2-6-98225cfb50cf@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260112-sheaves-for-all-v2-6-98225cfb50cf@suse.cz>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=hFImr025;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 193.142.43.55 as permitted sender)
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

On 2026-01-12 16:17:00 [+0100], Vlastimil Babka wrote:
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -5727,6 +5742,12 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
>  		 */
>  		return NULL;
>  
> +	ret = alloc_from_pcs(s, alloc_gfp, node);
> +	if (ret)
> +		goto success;

I'm sorry if I am slow but this actually should actually allow
kmalloc_nolock() allocations on PREEMPT_RT from atomic context. I am
mentioning this because of the patch which removes the nmi+hardirq
condtion (https://lore.kernel.org/all/20260113150639.48407-1-swarajgaikwad1925@gmail.com)

> +
> +	ret = ERR_PTR(-EBUSY);
> +
>  	/*
>  	 * Do not call slab_alloc_node(), since trylock mode isn't
>  	 * compatible with slab_pre_alloc_hook/should_failslab and

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260113183604.ykHFYvV2%40linutronix.de.
