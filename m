Return-Path: <kasan-dev+bncBCT4XGV33UIBBJVX37FQMGQE7O6BEDI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id EGSwHKnbd2mjmAEAu9opvQ
	(envelope-from <kasan-dev+bncBCT4XGV33UIBBJVX37FQMGQE7O6BEDI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 22:24:57 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 174BF8D9EE
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 22:24:57 +0100 (CET)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-2a0b7eb0a56sf44971815ad.1
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 13:24:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769462695; cv=pass;
        d=google.com; s=arc-20240605;
        b=b7vIMUBhIvgp/HMY/lRZaRJPTjAqUNDv71Z6bxVvJklXG6YhcphdZZ+ACrvaUBmLwA
         wcZ20cPQSnocMKQkUXfNMswzXhXMY4ONEJTzj0o/6Ie9K/hKPmem0R67oppdQFUYPiBo
         Z4n7Cphk8S2mTTAaOSY7wxhIGIy9mY/V0hAIf3CvxVcj1kmkhTNSsgvtX2nAPRqebk6+
         Zc0NIPzagb3FfAs/bfZ3AL5HNmCyiV5rNDfTYQ0YDHF3ab133LfJaas1Ui1AkmvHYsPL
         L3S+tQ0BhcMovDwvxED8HSKY/h0R5MmVhO0jY8iNv45ofnaD8IcSHWzmJuR5oQQuZ2c+
         stdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=4VxkIHQ+Vdz6L8Mk67XlOHfpF/QEUNFmlaQuxyKd96A=;
        fh=vwWkOZPOZtyJya9R9SZ9CBZ0D4ehnzBlOmKERIWm9Ds=;
        b=VcumC0ipv+UFQn2xkJ0WOq1MLfyOj+H7c/w13Xs42c6+QU+G+vqPL7wyTGYJY+iabU
         01gMGPYHg2JFH96oTYzOI+CwJaEpzn68edL5wWoNcpyvACL3LbKWw7yImBLIrPgb8fN4
         /ZwPkPQFUXSKzYoXIrK9LhpCQaC5mC6ROmwsDK5/YnlRmNqWEHvrfrh59jh4I7h+dBIr
         QLKvyJdPECqbOoXs3yioB1ulUJcek3J3dBFJ75k3wY/R1HtWlXPIsMOjNMZk79u+375I
         xAP4UqqhDO++n30+mwEDRAygzGAXHPl1OuZw/pIUqzNPBQq7p7hCL/I5/hsDoxWDYmRN
         yfsA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="RIk/EXZ0";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769462695; x=1770067495; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4VxkIHQ+Vdz6L8Mk67XlOHfpF/QEUNFmlaQuxyKd96A=;
        b=KuVkpsF9MujSbmv/dKOIzSTcnTNSoHmM/zoR1rZ7Cwi7OC7D+VNFl0bVyqrOpTlg5D
         QH+mGSQE/h7Fr7jn9Tl2oX96a3gFYC38cVUCaY0HWVvkcItP1UY3xvDQTxJUKbONNjIQ
         jfXCBbzkDolYrmttW1RyAx34CJFveQvrlwkaFTYN2uBOZET4OCTwxux4N7uLqLP/xoNa
         DkIdisuj+m5GUW4TiPK3b87T4HzJqx30jXA3zmjAJX2M14N/5batSr1RMMQhMtCwzmfk
         L+eyi5R2Sv3cjxTTyz5bUpsmvf22c2sQRtBRMMenswW8k8M1ehqgN8aSnDdz8Zzb0e31
         xXtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769462695; x=1770067495;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4VxkIHQ+Vdz6L8Mk67XlOHfpF/QEUNFmlaQuxyKd96A=;
        b=oTMMXWQWqc387ihP0yP8c4eSQ9oeUNWYgv9sesA3gc7LNqavvYcIHiRuTGC6HCbzWo
         j3cm1wgq5M7+0MWQmopvKrI1xbPSNXJNrAJfFtGT9NtesWTWW0d66bYlSGPJnXvr7WhI
         bdpjMR8m9TuUpwgK1mF7ilusbarfZ1BsACJ3ttZK773Phrnw+BtruX342tQ838xxxhoA
         vzbjiualPrEFSJ5BHU6XisxJUi2QDCRVgnjbClbkppvWNS20gaUNBafY8iD7hGWS6gjv
         wm/X6JwzWEyrGk2arltqtBVikwefTMtdKgbXlf0FZp988ikn979wlrJDlrJtJsXoVJVT
         CKcw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUN31wH8KgUUPwjZWneLVnNJVOKR+FzZWmEw446WDETkKcNZhu3TiKxKelVNnSRPb45+58Hmw==@lfdr.de
X-Gm-Message-State: AOJu0YzDeWF9xx+AI2YmXktNBPrt+247W3+W6lr3Y0egtYdcqeFT3V/S
	8Jm3L5nnBZc7pFTCmSOOHwJSgr41yyHKyyfq3XUW0NWNzfj9MXuFed4e
X-Received: by 2002:a17:903:3c6d:b0:2a7:5ad3:79eb with SMTP id d9443c01a7336-2a8452c27bcmr67847295ad.35.1769462695305;
        Mon, 26 Jan 2026 13:24:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+H24ui0s0rp4cmRGOXcIPGXGEfYBwHSUzNb9WkoVAd0jw=="
Received: by 2002:a17:903:4511:b0:24a:ffe4:1ba6 with SMTP id
 d9443c01a7336-2a7d353171cls38810705ad.2.-pod-prod-05-us; Mon, 26 Jan 2026
 13:24:53 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUGakuvSseYjNCzJcY8e0Cfz1EA7wNOpmC2Ke5tnHuuVMqkoC1qyCsQY1X6oy5vu1IglYQauGTbfTY=@googlegroups.com
X-Received: by 2002:a17:902:d511:b0:295:560a:e499 with SMTP id d9443c01a7336-2a8451fb94dmr57252235ad.5.1769462693218;
        Mon, 26 Jan 2026 13:24:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769462693; cv=none;
        d=google.com; s=arc-20240605;
        b=hcs0itSyMFILwQ97HjPOsGbTcEEXtS4wfsz5uqGEjlikqnhw851EoufHjMaNojVpiq
         SWWA7t3vr69XCDZneGSz/XoAzHscJsapSRHUG22/MexRqEc8Knv8ssqO2QmOqViIVMSk
         bdlpa0axIW9QD9spoY2VVwbkutnB5PmNj+LKXMVgWFO79IBzOGsgyYz/MQupxo5pGw/p
         7/OUF/Sdfs+aqBA0rHT9rlZ6wlOAzznrc54grNOkbYm6ZV1JxtXkoU6Kv4wAjBTnhsiV
         j8CC0eJZj0KZO7VPc+LlfacHIjXwW0agoW8srnj9aId8uRimLclQKufm4pOXp8GCPMiW
         f2+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=6t1cewAY+RyKnl9MkS4rDpxQSN+o+t65bdYY0BgbhZU=;
        fh=Dhd7dfKq0N6Mf2E0ujevaAJxg/Whoqu52FaX5606aAw=;
        b=jguMgdQaSQ/66Lb9ut9sb1lvW7rWBF6QdtvSmyuvKiR3CyfWFOVBSE8WV/5zsjHyEA
         vY8E67nZ0LtGFEXwSMGYcZgYvzVeUngPvIpGwOlldHzWzEk+UA+MGufzVaC1Ve3cTc9S
         hM+eE7Zze7p1t4aDmeIzEQufMd+hPzHDyrNons1Z0k4s4LL3MYqnfGuPSLdQC+mxqUc8
         uZiuP/4JsHF51Ca9sk1i0pooL9Te8xLbXMqp4LbUQalQVtKXtGxbUMNjUpItEF3tWa3+
         9AtDd6i2yt8lDXeUIWXqGcSlI0lw2euoH7mV2CQTgQmQcfk9qtmcXRYhdYiFwvDFA9PQ
         fWCg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="RIk/EXZ0";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2a802f9e895si3017645ad.5.2026.01.26.13.24.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Jan 2026 13:24:53 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 251A760097;
	Mon, 26 Jan 2026 21:24:52 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6129FC116C6;
	Mon, 26 Jan 2026 21:24:51 +0000 (UTC)
Date: Mon, 26 Jan 2026 13:24:50 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Andrew Cooper <andrew.cooper3@citrix.com>
Cc: LKML <linux-kernel@vger.kernel.org>, Ryusuke Konishi
 <konishi.ryusuke@gmail.com>, Alexander Potapenko <glider@google.com>, Marco
 Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, Thomas
 Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav
 Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>,
 x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Jann Horn
 <jannh@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH v2] x86/kfence: Fix booting on 32bit non-PAE systems
Message-Id: <20260126132450.fe903384a227a558fab50536@linux-foundation.org>
In-Reply-To: <20260126211046.2096622-1-andrew.cooper3@citrix.com>
References: <CAKFNMokwjw68ubYQM9WkzOuH51wLznHpEOMSqtMoV1Rn9JV_gw@mail.gmail.com>
	<20260126211046.2096622-1-andrew.cooper3@citrix.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b="RIk/EXZ0";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 172.105.4.254 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [0.29 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MV_CASE(0.50)[];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBCT4XGV33UIBBJVX37FQMGQE7O6BEDI];
	FROM_HAS_DN(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	MIME_TRACE(0.00)[0:+];
	DMARC_NA(0.00)[linux-foundation.org];
	RCPT_COUNT_TWELVE(0.00)[14];
	FREEMAIL_CC(0.00)[vger.kernel.org,gmail.com,google.com,linutronix.de,redhat.com,alien8.de,linux.intel.com,kernel.org,zytor.com,googlegroups.com];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_NEQ_ENVFROM(0.00)[akpm@linux-foundation.org,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	NEURAL_HAM(-0.00)[-1.000];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[linux-foundation.org:mid,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 174BF8D9EE
X-Rspamd-Action: no action

On Mon, 26 Jan 2026 21:10:46 +0000 Andrew Cooper <andrew.cooper3@citrix.com> wrote:

> The original patch inverted the PTE unconditionally to avoid
> L1TF-vulnerable PTEs, but Linux doesn't make this adjustment in 2-level
> paging.
> 
> Adjust the logic to use the flip_protnone_guard() helper, which is a nop on
> 2-level paging but inverts the address bits in all other paging modes.
> 
> This doesn't matter for the Xen aspect of the original change.  Linux no
> longer supports running 32bit PV under Xen, and Xen doesn't support running
> any 32bit PV guests without using PAE paging.

Great thanks.  I'll add

	Tested-by: Ryusuke Konishi <konishi.ryusuke@gmail.com>

and, importantly,

	Cc: <stable@vger.kernel.org>

to help everything get threaded together correctly.


I'll queue this as a 6.19-rcX hotfix.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260126132450.fe903384a227a558fab50536%40linux-foundation.org.
