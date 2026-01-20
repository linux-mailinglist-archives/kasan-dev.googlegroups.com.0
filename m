Return-Path: <kasan-dev+bncBAABBWHKXXFQMGQECBSBKAI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id AEi8Mumib2l7DgAAu9opvQ
	(envelope-from <kasan-dev+bncBAABBWHKXXFQMGQECBSBKAI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:44:41 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C20E4684C
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:44:41 +0100 (CET)
Received: by mail-ej1-x63f.google.com with SMTP id a640c23a62f3a-b86fd61e3b4sf591963266b.0
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 07:44:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768923881; cv=pass;
        d=google.com; s=arc-20240605;
        b=lWjL6fEtJssze8kbGxrpxsVEQl9+qeP+vZMB8seKpsTg7XQ0fhMQWtv9iqI6oGqYU7
         uNxQGfeuBNz0etVEVzdoeIUGpEzGhYI2uDORFBrNQuZbqyFDOsXYI1g+vCiNDrXq5He6
         uiyGyGQL3VhA4UsfSFh3H9OEg2ZuJjBUa1e/NFBebpMgxsuKQJQTWGZn3yzivDnWO5F4
         ds0hviiKDgb8owFQb8XiwdJFCZRt9upVB/PwrfmzcHHQ6CKnkrZYsoN1jNF7iv5NUy3C
         lHj93GAA+hc9fscMRMbCoUL4C7YzK9dUGhE1nQ5573Pt1xRp8R4C4pVIdeN7KZgyUi6V
         Y3AQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=hWsJhVpKRKFLVRFhacA0UkUzIyDcfpZNl0oru+FTqPU=;
        fh=zJUTsDlM2Ob9hmKuP38ZAQgdgv5il8caUeKfvK6442w=;
        b=juNkFuZZedS7WTFE18I0l0vG7OTJSRTzDUxRaNNHMx5Ig0zyDK4zitiXHqf6b7CgsN
         yTNtrvySVedqiyoiuFcjB/wuCBm+BTzrDcb4+YPKrun1qStFITPm3k+dXfkBQttSvcKy
         cZacNvCR+87c6OOtnhb56mxYLpUZDgghSqMxLkjxBqNgslo8tMfJmkhuuq2lYivogdku
         fIWn2EL3TOVCV4+5Zw5RokYHMc9RIhD7w7xVLdwfqg3mMN+dSaExb3O6vmKi9TjdXI0V
         9cck6A6MxvZHf00T8P2F57IgCnNo9xpD6vGoIo6+Bgq1XgNRr8fH+ocV9vnj6I9nThNm
         4HiA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=NI327+VQ;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b3 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768923881; x=1769528681; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hWsJhVpKRKFLVRFhacA0UkUzIyDcfpZNl0oru+FTqPU=;
        b=jTbhLHU4YCRr2sQg72ss/+68JMCdZaeLy/dN9zUh4mSPsCyFGO0hUdKKficICvWDk1
         VY9H/BjIYaTBHL2GMHfg4eUrQ1SAxhwmAOKNU/P3eK4/+jxSVIOh2Ax9qJHAg43Vjs7o
         05EojlJ5o7caELLa/QyFa8f9/4HAQ9aOrA6JXu1z4R3tz0qXvkFMYVdIPBqlLdoFYjtC
         CHxSyouKAt1Ib0TXBtR1in/EBfWK/Y7DPcvbARbtaaKa5TA/Ji0fEGZmKvMDofsXn6El
         D1u/bOOVlh7oNtjn8m9DPFI6RgyqQtbOXIfNtXTwQXUrYnaVSoFAJ5EQiOQA6WO6DYX9
         um6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768923881; x=1769528681;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hWsJhVpKRKFLVRFhacA0UkUzIyDcfpZNl0oru+FTqPU=;
        b=k+w39Vj6NsnNBmpC9kzrFywKyu8hAPJFssdKI0x9sLoWmcEcybLhupMbypt04j+UY3
         Ze2orMMm6K62z8LhLifQHJrfrUptgUpWfRkNPFSohNHJvOSryq2Ez69GtEIwRkTPFORD
         4cP8UNQlxd8WYISDuoy2lqgZmxXwt+G+Mby2Dyabc9pSu5rcFhxU2ZUNx81MVs+JjX3L
         D1rqXkU9KjhfyyRzN/wuflLBxOGslu8pQX92f9KwKTtJYFWD69XGLduUhfr9a+8acHN0
         lkfaF9YWV+rgjnMSAJXGOAlWc2Fu5WkFtIeXnNJMdi6ens2YVObXYkiVji2rVu+Ck85G
         FnvA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWPkVOwVKvfBy1IAAsrUN1WBIjK4IBpYyORcPXa6zQrjVbSRVCcW0O0t0L1mdafJhlQAWuzsw==@lfdr.de
X-Gm-Message-State: AOJu0YyUu3wXSU0tU323Zr/iUIYkZUFV5KkZcevOUknX2RrntkA/KsgU
	io5BH0YwqO05Vub/lMBGMxIi1UsjTdXaqAKpieuXlqw5yPLpwB2RtduB
X-Received: by 2002:a05:6512:3ca8:b0:59b:70e7:4128 with SMTP id 2adb3069b0e04-59baffeede0mr4696980e87.53.1768912217301;
        Tue, 20 Jan 2026 04:30:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+G+HFmaJkCIzULP+MltiAGnWMd+4yhIf9Cm9VQ2BdTnSA=="
Received: by 2002:a05:6512:31cb:b0:59b:6a98:7132 with SMTP id
 2adb3069b0e04-59ba6c4ed66ls1162212e87.2.-pod-prod-05-eu; Tue, 20 Jan 2026
 04:30:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXMG+zTkUYYuD+F2fALUaOnFCOVrfA3H/71f0gT8MwRMPmRdjO5bHgNqe3Rp5EiVRymzaDTMUsbvoU=@googlegroups.com
X-Received: by 2002:a05:6512:2316:b0:59b:7803:c7e6 with SMTP id 2adb3069b0e04-59baffc6d9emr5359485e87.33.1768912215015;
        Tue, 20 Jan 2026 04:30:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768912215; cv=none;
        d=google.com; s=arc-20240605;
        b=acnqEP0JiIsNEDX85T2mJHxCPFcA+LZ9ES24dNqRFOMTtbqR1CX35qIm3JM/rCR5eo
         TVgh8Ge712EuuvsxUig8rbWzWBqoL/tSq2JQXoGrD//a74l11aBPIbN0Rmtrd+84zfSZ
         QtKYPQ5s8SK8MzDwlKY/CyeNxPMjE4cwNKPZLptz3KUgc0si8PZnsneqtlN2ZqH3jElj
         b4E0TM6byND1UabKdh0SoZQaMCqxdoaNMo2B9iGi2TUss6GceQq0yKI4Sg4gQJfMHnMK
         /Wp5lD6v9UO87G/FULmNT5Dy0K+zzrxcgqhqhv1sJD/uGyv/I5t4VtUFes73DJVbniW0
         1eAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=U0l4DlrcsAB29u1FZ8RfgxXvBj6CMA+nJmNa7xiJio4=;
        fh=2eNRZ9ECquILDe9T7DsfDKzbtYQIgOYM00xcI0sJ8bg=;
        b=VLXk9ynARfXSVpYjhBJvekwIswpTpsAAIwEUHHT0f2hchSgDcY4ibJFVae+r41CbeS
         BN3qUyNmc4labWc/w3LX1s0nDeHq+RUv+3RKtJcb24t4jROw1QvcdFgZEJu0BviPRRW/
         RVjdMBhIvWUODKDmnZgPe2KKmB7k4Xm2rbmpzkCayQsiT9CoMl/Sli6iqVqlFFHw7n3J
         sb9MbgoQxNMG0EAi7v3MUVkVsuJaXFAeN5kKL6Bj5epkXA4+h9Kjp4xcjMzBK4Gz0zxS
         xjiSw6ctCfhQ7OOMggl7WAbXotbHIFfXPGjUg+NdTIo0v+gFA8wL8Yt+Y2Ot/aCK1LYD
         rd9A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=NI327+VQ;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b3 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-179.mta0.migadu.com (out-179.mta0.migadu.com. [2001:41d0:1004:224b::b3])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59baf393418si222369e87.5.2026.01.20.04.30.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 04:30:14 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b3 as permitted sender) client-ip=2001:41d0:1004:224b::b3;
Date: Tue, 20 Jan 2026 20:29:56 +0800
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Hao Li <hao.li@linux.dev>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Suren Baghdasaryan <surenb@google.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 12/21] slab: remove the do_slab_free() fastpath
Message-ID: <yejhiw37av3o23z6s4oewlmhip3iqxxkkfcjp2jhlo4qf7nm23@hojkan5ym5cv>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-12-5595cb000772@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260116-sheaves-for-all-v3-12-5595cb000772@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=NI327+VQ;       spf=pass
 (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b3 as
 permitted sender) smtp.mailfrom=hao.li@linux.dev;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=linux.dev
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
X-Spamd-Result: default: False [-1.11 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MID_RHS_NOT_FQDN(0.50)[];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[linux.dev : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_COUNT_THREE(0.00)[3];
	FROM_HAS_DN(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	RCVD_TLS_LAST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_NEQ_ENVFROM(0.00)[hao.li@linux.dev,kasan-dev@googlegroups.com];
	TAGGED_FROM(0.00)[bncBAABBWHKXXFQMGQECBSBKAI];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,linux.dev:email,mail-ej1-x63f.google.com:rdns,mail-ej1-x63f.google.com:helo]
X-Rspamd-Queue-Id: 6C20E4684C
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Fri, Jan 16, 2026 at 03:40:32PM +0100, Vlastimil Babka wrote:
> We have removed cpu slab usage from allocation paths. Now remove
> do_slab_free() which was freeing objects to the cpu slab when
> the object belonged to it. Instead call __slab_free() directly,
> which was previously the fallback.
> 
> This simplifies kfree_nolock() - when freeing to percpu sheaf
> fails, we can call defer_free() directly.
> 
> Also remove functions that became unused.
> 
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 149 ++++++--------------------------------------------------------
>  1 file changed, 13 insertions(+), 136 deletions(-)
> 

Looks good to me.
Reviewed-by: Hao Li <hao.li@linux.dev>

-- 
Thanks,
Hao

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/yejhiw37av3o23z6s4oewlmhip3iqxxkkfcjp2jhlo4qf7nm23%40hojkan5ym5cv.
