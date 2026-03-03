Return-Path: <kasan-dev+bncBCPLLDFXZQHRBKGGTPGQMGQEMSUPMRI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id +OV8NivjpmnpYgAAu9opvQ
	(envelope-from <kasan-dev+bncBCPLLDFXZQHRBKGGTPGQMGQEMSUPMRI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 14:33:31 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F7381F051A
	for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 14:33:31 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-2ae57228f64sf19222515ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 05:33:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772544809; cv=pass;
        d=google.com; s=arc-20240605;
        b=kS3Gk4DzNUmvauL1q4+jXOaLO0br6XbABKn2z6S+X8dHQM64EuKa0lRU4q42lL7krU
         YKsRPEs/ZGlbx9Ifds+nwbd8xNDT5XJyP1UtGiNPYAErkk+30eZuOcbrhcX/x6kdESwC
         CoHQBM1bpFUzWOMe2I7T9eu6W/wfgDCIqiQ4nyun/+aW6DWruoBCLtWGQdxIFwkKnDVG
         DwxO+NMFQf2Jb2oPPca7QBX/rQAcYhqjqXNv0K+qy+qReizd9GFY9jGizf7WW8vVef6K
         6ZjydNxFdrwOBwhenqXx/SvwLUG0Y85H6MH0T567e0O3qRnyZZLwKKaOZY96IlLMo7Iz
         pVQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:references:cc
         :to:content-language:subject:from:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=jhghfhmvU5WR9vFHrzvfbzCvp8v5NcupzSiO/SnWMXo=;
        fh=b6/vN/ocvG9cdM11cxaVyhX/BBaG+xoNQej0BxFGbHA=;
        b=kFCyH9/Jv3ZzDRZnTjKjpjYrjSXmKQr1C/MPvoOX4489icsMwl0BSfWRf11WX3kcA7
         3ZUxIisaCjj20k8MjfQ+NwkE8XJv5h0T05jZ7mMzFsGJEEH/h2eo8zbSokYpY7LrIpmF
         HdAY1BxWuSo9AAvROAwIevC49re9k8GlqDLL/KUMFq+f7U1Eailh9GN/ShfL6+Yqnw97
         zPSMerXyC0FEg7CMmfgGdvVSabtRX9RyZO7llDhiw4pgUu2Mrf1qk8JOLhhW4VDHg6ma
         rMlfBTsmULwYUTHbAeAywCVV8b73aYbWdVZPyJzQmn0PBMistwQoDfsjQHZwUJP8STWz
         JU7w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="HAW/33zE";
       spf=pass (google.com: domain of vbabka@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=vbabka@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772544809; x=1773149609; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :references:cc:to:content-language:subject:from:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jhghfhmvU5WR9vFHrzvfbzCvp8v5NcupzSiO/SnWMXo=;
        b=qAhPm8iLSj1eiWZw5pWoSfbjCocgGTDUemWZjuZuHLpQxku1wzw1lPa3ecilCPUhUs
         i0tEtKQeKQKjs8mJVSetIreX5FiQ0B14xDXDoYq5OGfNA5ENrZAimGrC89oxRxtdlNOz
         TCFVh7rBnnP+lv0xCD9ixRsUG1t4QbfhwBtPHmz6H4dRSrn7mjxSrL9vqQn4rxka0FJN
         eU9tfUazP6/kV/pX3N++J/TZy6v/w968ROfRq2QIEZTaqXtOfa7eYAfk/NiW9u6G1bcl
         ugPWPO8Mm3TW5ND34t+PE20XUHjwzgeVwYXu5lcPNNERFsegm63QU6wLwqXKshmLS85k
         Y5MQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772544809; x=1773149609;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :references:cc:to:content-language:subject:from:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=jhghfhmvU5WR9vFHrzvfbzCvp8v5NcupzSiO/SnWMXo=;
        b=xONCT6amnH94Mb5bedwPCR2/o3+M02vdf75/uPxm51BV+X9LSfDkcWYT0s4CyCouc4
         Vs1UL6DM3YakRfLvojd3lHstTYU9Iy05A90z+zz9P91nBkeuqgL9qsSTQOk9uZ5dmXT4
         16pNsRHv/ZTCGdlUPGtu4oUeoge2ue3cI/W0jfzqYM4UAl1DnWXoSK2ZW54hfiQ+n9of
         KkQ7IFgkdPzGpy+dsbX+DwEu//eMGcFtWEOx0RXPAlxZkRdt3tO/NvK7NrZQcMVrSdPc
         VBZkzCV+u8FtBrRWQSWck3uAZa+gv1feeWUm/wP4Xij5955Ggyqnvny1XWHuIsEvL9Dy
         BkTQ==
X-Forwarded-Encrypted: i=2; AJvYcCXbYwrHf/hRU2wbbT0klGDf0QHiUHyQPhE/SxDObweUoJxV6A9V/lQSTogc8+vB6hcv7W685g==@lfdr.de
X-Gm-Message-State: AOJu0YztlVSb8M6A98j224V+Pgo6VTLd77iiC6D5ovhsAH+OcamSRpji
	JTglI/WaK0yfYcvklWsHiONRXb4YBIte6hk6BuQzDRC3zTtiQqQlFjtj
X-Received: by 2002:a17:903:1aa3:b0:2ad:c66d:ad06 with SMTP id d9443c01a7336-2ae2e4d603dmr165618125ad.47.1772544809220;
        Tue, 03 Mar 2026 05:33:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FSvgNV9bWTjrDcMNyK6wc9XSg7MKZjlXw4mJhSi7sXfA=="
Received: by 2002:a17:902:7c09:b0:2a9:622f:5ade with SMTP id
 d9443c01a7336-2add8071fa3ls43019735ad.2.-pod-prod-02-us; Tue, 03 Mar 2026
 05:33:27 -0800 (PST)
X-Received: by 2002:a17:902:d4c1:b0:2ae:4d44:c647 with SMTP id d9443c01a7336-2ae4d44c8b5mr90025205ad.37.1772544807616;
        Tue, 03 Mar 2026 05:33:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772544807; cv=none;
        d=google.com; s=arc-20240605;
        b=G04OpJX1bhNXvuAjquFixm+lEL+vEVHtYr5uMGDzyrt/etGXaKEL/UOAsI4lAygfBW
         FS7J6GL6HyrSf6ExszE1EwzE9aXFgPwg6iAXvoBrjjmmQAv4depAjPcs2kZ+lk+uRBT5
         1iljMwH5pxxgGa6LrIA7Ei8C0YthvvmFKGuP7873FwbOgSBNd9aQeThTlXILKRFA3X/l
         u9M+6GCqn3bMBrMgDINfklpTMlcC5ZTvmOeuqk10XnWChEz9eEtFDgvu+eNcMTJp9xLo
         3HAzMTs+8EkdsAJWG+8NWLu1xC3S1/JFvR3JN8W4R66RxFYvF3Qb+Gugq02Zq0WuZkld
         rnxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:references:cc:to
         :content-language:subject:from:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=K2Yb0GPjtIbsH4Mqwvk4O9q7Tn9IQ2N1PxFqR8PbP3k=;
        fh=I4/HZAX35QOw+dZeihCsr0cFLi2Cp6hWp6Y11nqwfR4=;
        b=cJXMVLIOOpGDtbLj/BcRrX3NP3uaiyi9r7F6DJhtCgWa+Y6nDigAojBPot7d8LYkuy
         7GozkraTx5Q1t2Dgh3EATwlG1KZne43XsSXUqYqyX6fvUTZIdWzjUVfwTdIxnr/2kiZr
         jSULrusO1cZ0Y98WAIXP34dV4c0C0QVJrpYEsSqxFUxlU2QRn6GQjdPcE5Wd1gfqC4rf
         cJD8z2ilragn2LBwshDph33iA9CvJNT3SbVGzzCwqlO899Y54S8CSKWf9ycjBoAx8ST4
         6HGLuAficgWi9vg6QQ4n9ZGZS5JoCHbsP3UQODt0+tZTWlmi76hJfYNfDU5ybzYiM6DX
         EsWw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="HAW/33zE";
       spf=pass (google.com: domain of vbabka@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=vbabka@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2ae412e29fasi3115155ad.8.2026.03.03.05.33.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 03 Mar 2026 05:33:27 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 7DBBD60123;
	Tue,  3 Mar 2026 13:33:26 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id ADADEC116C6;
	Tue,  3 Mar 2026 13:33:22 +0000 (UTC)
Message-ID: <500ba707-53c9-4037-86e2-973c71ca3d41@kernel.org>
Date: Tue, 3 Mar 2026 14:33:20 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
From: "'Vlastimil Babka (SUSE)' via kasan-dev" <kasan-dev@googlegroups.com>
Subject: Re: [PATCH v1] kasan: docs: SLUB is the only remaining slab
 implementation
Content-Language: en-US
To: "David Hildenbrand (Arm)" <david@kernel.org>, linux-kernel@vger.kernel.org
Cc: kasan-dev@googlegroups.com, workflows@vger.kernel.org,
 linux-doc@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Jonathan Corbet <corbet@lwn.net>, Shuah Khan <skhan@linuxfoundation.org>
References: <20260303120416.62580-1-david@kernel.org>
In-Reply-To: <20260303120416.62580-1-david@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="HAW/33zE";       spf=pass
 (google.com: domain of vbabka@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=vbabka@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: "Vlastimil Babka (SUSE)" <vbabka@kernel.org>
Reply-To: "Vlastimil Babka (SUSE)" <vbabka@kernel.org>
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
X-Rspamd-Queue-Id: 4F7381F051A
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [0.29 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MID_RHS_MATCH_TO(1.00)[];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBCPLLDFXZQHRBKGGTPGQMGQEMSUPMRI];
	FROM_HAS_DN(0.00)[];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_EQ_TO_DOM(0.00)[];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[13];
	FREEMAIL_CC(0.00)[googlegroups.com,vger.kernel.org,linux-foundation.org,gmail.com,google.com,arm.com,lwn.net,linuxfoundation.org];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	NEURAL_HAM(-0.00)[-0.999];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	HAS_REPLYTO(0.00)[vbabka@kernel.org];
	DBL_BLOCKED_OPENRESOLVER(0.00)[arm.com:email,googlegroups.com:dkim,googlegroups.com:email,linuxfoundation.org:email,lwn.net:email]
X-Rspamd-Action: no action

On 3/3/26 13:04, David Hildenbrand (Arm) wrote:
> We have only the SLUB implementation left in the kernel (referred to
> as "slab"). Therefore, there is nothing special regarding KASAN modes
> when it comes to the slab allocator anymore.

Right, thanks.

> Drop the stale comment regarding differing SLUB vs. SLAB support.
> 
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Cc: Jonathan Corbet <corbet@lwn.net>
> Cc: Shuah Khan <skhan@linuxfoundation.org>
> Cc: Vlastimil Babka <vbabka@kernel.org>
> Signed-off-by: David Hildenbrand (Arm) <david@kernel.org>

Reviewed-by: Vlastimil Babka (SUSE) <vbabka@kernel.org>

> ---
>  Documentation/dev-tools/kasan.rst | 3 ---
>  1 file changed, 3 deletions(-)
> 
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index a034700da7c4..4968b2aa60c8 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -75,9 +75,6 @@ Software Tag-Based KASAN supports slab, page_alloc, vmalloc, and stack memory.
>  Hardware Tag-Based KASAN supports slab, page_alloc, and non-executable vmalloc
>  memory.
>  
> -For slab, both software KASAN modes support SLUB and SLAB allocators, while
> -Hardware Tag-Based KASAN only supports SLUB.
> -
>  Usage
>  -----
>  

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/500ba707-53c9-4037-86e2-973c71ca3d41%40kernel.org.
