Return-Path: <kasan-dev+bncBCCMH5WKTMGRBYWKTPGQMGQEKMGG4RY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id mDIqFWXlpmnjZAAAu9opvQ
	(envelope-from <kasan-dev+bncBCCMH5WKTMGRBYWKTPGQMGQEKMGG4RY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 14:43:01 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb138.google.com (mail-yx1-xb138.google.com [IPv6:2607:f8b0:4864:20::b138])
	by mail.lfdr.de (Postfix) with ESMTPS id E9A181F0863
	for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 14:43:00 +0100 (CET)
Received: by mail-yx1-xb138.google.com with SMTP id 956f58d0204a3-649deeeb00fsf7342351d50.0
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 05:43:00 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1772545379; cv=pass;
        d=google.com; s=arc-20240605;
        b=bvGdBHpadhqGpXHlpXY9yFS2aWkh08EuOOKAV/8h/Mv1ln8jmwh55IJ7hYPBC8UJKQ
         N6IFgJyettiwcmE0HKedk7HBQ3Q73YqrCnG4FqBxpLNhqVsDVpwRLA4VZvWEpG3qQkUh
         glKA+ISqmA8jycUU34XxOyNr+qyEbJ//rAcEIgD55B1FrjCNZIQU94M7ICEZI+hmu2NX
         ypEZMgIRYJDohNd1boY1SUXIdmRTtfaVyVFiDw8tX56Ou9ektEgSjkDFexT2X1FCIbh1
         mcX7c9OodiqHUb/9XXaZNhrc+i5P9dmJzHqegEjykFB5C/P7ZLv6u2Jnyk+PK+nDEGJ/
         HOeQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rdr2j7RBTBWSjH47WMEFUsoiQblffg42NwE+TWYWzbA=;
        fh=oAzyYtSfM8w9tNPrPlgFlcWGgc401vf3nYIZlcdUepw=;
        b=ZN47+EEQSxB1295jcHAI+en3eKI3q5cp2kI60+T2iv8bNSYFV72RkQwCO287AspiRP
         W8qd0bgJOoVtHBGh0V6imoWvHDBH+hYctS7Lku9kVX9SzMT7mBqQhgzRTDp/QgqlZNt5
         4O+k7r6ExLgAq11x12fwQFj2sehT9OehcIudFrndfeFAqfd/3BaMuzrfPvQgat6nKUt7
         VcI6xk6cIVIQ0Mr7BYWgLwmydKgwMT1+fByk57cGAuFrIPlDP0IzoRmBoU9WRiAA84ci
         k58CCbVXuTh5nrtcHABYf4lYVNkshZ9GxRBE/OyH7j+uAXDNFRw9roXYh8cdqoF0PvsO
         kQSQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=sydavu+b;
       arc=pass (i=1);
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772545379; x=1773150179; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rdr2j7RBTBWSjH47WMEFUsoiQblffg42NwE+TWYWzbA=;
        b=pL+7LYPYwDEXFWlPvpkx+qTFYmeH6js9q3rlhANYdgIfGD+4Arv0u9dm2/bhXmMEth
         NnCoypm7UgKeNUS3eBYc2NwUcRePDeiVaZc+wVLmCpNpbxgiSBAng+9SYRoZWPo86m3u
         DcsdKrloS09QkAUALR+gk33uatOMdNwoqYaeBduN6VBLI9ZfWwzfrITZlsnIzTyVSlSA
         Id1z0iMui9ec5akdlJjS3lOKFeyxpOWLP87m9Qb3I4YdzMkm69HSgjc+vW/21NiKEu09
         0l9bweIjPCA+LMBUhzJsE8J0kqJbe0EDs6zA87dmssvrFTAseJrZsg1EwOzwpqnCLMnd
         Toiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772545379; x=1773150179;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=rdr2j7RBTBWSjH47WMEFUsoiQblffg42NwE+TWYWzbA=;
        b=jubyA5UTIwNiE1jjQ0tmsbftVYHiC5zvfSIdNmoisD6L3MjjPXLjTvEFQD3yVlZRrx
         Hcq3ewuS16/Auch3YkSP1uvNzyJ7140HronFCtQx5FxFtJXDD0CdXlvIdg7xUSnbXCo7
         oMBm59RXsR2q2whSLY2f+/KloqLoog9oicOwNx60SWEKMMXNRkPBdEzcUmBEHnsMb5C4
         rwWwAWjvPxk1aQfYWEi+Dv8W4of67eOqbVjkq1hU0Rv6MlIr309ESQyTPML0kjDOZ3Ib
         VepCg8sVWBQ3bQ8VHKDqizjZaBlzLLllhG+zakYP3Irsxc1fFZmx3u1oq/h/TS0Kb74R
         sG1A==
X-Forwarded-Encrypted: i=3; AJvYcCV8Et9bYIALyW0qEdcOj5JAy3AhwM7ld5+WuCFzVtHlqDvhGAorG+11dU5i+qD+Q8KrLkKRPQ==@lfdr.de
X-Gm-Message-State: AOJu0YxsWyV/0dWjymF1NQMke7xUBTrb+Li5DxY4iay6ceVdP5IV6g81
	TbegmX5nI0aJ4175K6ZlBSTByHyMVKLaNT20sVw3hQowdX8LPIP/SNz5
X-Received: by 2002:a53:d745:0:b0:64c:aa01:55ac with SMTP id 956f58d0204a3-64cc20caafdmr9636560d50.24.1772545379256;
        Tue, 03 Mar 2026 05:42:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+E7/PgwodbVKkPAIXppVZsxXYgYOVyrzsZd/KDM1pawTw=="
Received: by 2002:a53:cf05:0:b0:647:27b0:1a65 with SMTP id 956f58d0204a3-64caa9e9bdfls1746976d50.3.-pod-prod-09-us;
 Tue, 03 Mar 2026 05:42:57 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUbCop/8Jzaou31g6lFVC07dvVYda8DSWOVx7eMaBOX7jelz/a5vbfeYmmOqS5Y/w8/Rie/clD2Onk=@googlegroups.com
X-Received: by 2002:a53:e143:0:b0:649:d19d:3b0c with SMTP id 956f58d0204a3-64cc23351a6mr8977277d50.85.1772545377566;
        Tue, 03 Mar 2026 05:42:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772545377; cv=pass;
        d=google.com; s=arc-20240605;
        b=UMF0bVkmNLnlHdqgmf4qsqtyH4UnznArZ9V5M8pyrZu8ZPZxw3wz96/2p/NTgKKBRY
         6ymtyJG+2J73zaRohaLEq9kssIYNqoNGhDY5GxxP7/zp2HesrQfD+OO8lc/wBgCVXMuB
         ZLorpVhKcpaBJLjORsgZcUVotgvJbYL9uCy02/5QhpMMq6ukZe5G5iM41iFxi0wgLHk0
         1Iei9CC13ax+xVF2L3QnqpI5gEr9RPmHKwFF83vXV+x9GqlmfSI7Lw4v2bTY4mZR+y9e
         sOINKg3gmkdw4R+8o5HkYn7AyAE/+34Wj5ijnMrlmhrWvyrvTaJuLcKLTPJSK5V5zRlA
         oWug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=2ib0jE0UROuqHeVvr4xE90sAVXgstdGcpgb+zpFuvYw=;
        fh=oevyeBiTEcr9+NlZuOt8uC/3Xm0wIstlgZK1oZ4DXPA=;
        b=hOS8W1QhvpBWH48xcnWYynl7L8aBZjPpnHrfHLQh4AUQhY01U7Pxf5BBTv3A3wS240
         nk4wTrZEsXksSb8paA2EzChrb7+36n5zloc8zXsfzaYdN9bx6QaSZhr+kD6KmhgcAftr
         0kdsbHpv8r9xR2AhUYuV1klwSeK/eAIdnyTYbDTbTD5ikGaVQuCYyjgD8UL4U+UQuG9j
         NTgnW/v2WZ0uF8HPNxQLIRuV9JW+vIhIEo5wiGkUXXL4Bke1kOB79N0VZy4EytmEOMYZ
         4PGSX7opRgx2njzQeEb8gr9x3M/YyhOHsQmKgAT7drcBpgpyDCbmtFnv7kSSnh1t37y0
         5pzw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=sydavu+b;
       arc=pass (i=1);
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2f.google.com (mail-qv1-xf2f.google.com. [2607:f8b0:4864:20::f2f])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-64cb766bb44si641540d50.7.2026.03.03.05.42.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Mar 2026 05:42:57 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as permitted sender) client-ip=2607:f8b0:4864:20::f2f;
Received: by mail-qv1-xf2f.google.com with SMTP id 6a1803df08f44-89a0ece9f14so7020016d6.3
        for <kasan-dev@googlegroups.com>; Tue, 03 Mar 2026 05:42:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772545377; cv=none;
        d=google.com; s=arc-20240605;
        b=Tai+33iWPbpvi4Hv7C8JBSzVDuDsN3mat+9/PF1ILQ+dPrH6Afjjfnd+sq+bAq+OiH
         QuY5+SFhD3Q4e/LFpJes7C7jMLFCaiqwHS8Qw2PobOcctEgE9SR9jeSSeeFLSOjatUec
         ZDzx1fAOu9zSYI1r1BWGnO8a+ieax30hyoEbBNCdqsXg3zv/UCPkM5CLjsK6J05fStju
         Kcij67Y4KJeCO7fXTwDRAYSX6n7GNQ8HwHvPWmPMNUQqQEMiCJOKZALd592OJVlc3JB2
         WzhOCXRHCjE5s8wOQ89J+plac7vzboSeqOKGzNAYskLchEnUwtuKDSYbTK8LAjy+ardx
         TmMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=2ib0jE0UROuqHeVvr4xE90sAVXgstdGcpgb+zpFuvYw=;
        fh=oevyeBiTEcr9+NlZuOt8uC/3Xm0wIstlgZK1oZ4DXPA=;
        b=lAJlsSAMuesAf97Aj3uo0iYjAjF0btWZl/89rLNtTdMZhxdIGbkv3fWX/8XjE62fJ0
         eq1XTpO0V1XkHaN68RYHXZtPhZZWaDg3Eq5p6pKnamjwkkR0/YqpIzRmxSeABWZu4qqp
         dN2FHM43ycg2L5D2TfkEgNxw64+6Yube1rC/iYGAeJsYpUzmxGAwkxHYDusqFvB97lU8
         5li0/2iYxwcaw2FCpTBMIneZzyS/VQ0PtJ9+EWyy61iMnB06Cz/8q+orGtOHhKwO/Li0
         nQdbKYzUokSxE3OSmmcTAZJXi0JTWmf3KEVce17kdXtErYoofegdIZ8oJ7uy8iK/nPYi
         2PZg==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCXQKChEApm25OGdjyaLtKmmhVtfDGKaoy09zTkODTQLnRWgIZqWpMZKqqp4Xk7WM/Zih2nAQjyPM7Q=@googlegroups.com
X-Gm-Gg: ATEYQzx7IeSv1y3IQqaabmI/2FNatfUTd6WLQdWpTVcM7bxn2/tN2uqsA33dNbfCeie
	Yu5f8LrHFN5FAcGNA6rc0NUPvwzaZR4vUPpUyAxFbQvrEDtmFefg4Ib2H0x7YF3+6U1hQJ1t0qD
	WICFQJTF71lLLie75V/RLMhKi2rYM45e/G+Mp966S/SFJU/oHZ9GxlESkaNwmVMSS9yLOPjyF8T
	QprFa8VW1K0+5HzaSg/K/a7iP84BBION8QLtxbUNVZiskKNlFInhBo/6d9/l3LjWHoJE81sj3oc
	MH5EtbSLD6x+vCXTGO8TLDYr+0kZ98UAXIWRtQ==
X-Received: by 2002:a05:622a:4d:b0:501:40af:96bf with SMTP id
 d75a77b69052e-50752989987mr225891971cf.68.1772545376634; Tue, 03 Mar 2026
 05:42:56 -0800 (PST)
MIME-Version: 1.0
References: <20260226020748.1282208-1-imran.f.khan@oracle.com>
In-Reply-To: <20260226020748.1282208-1-imran.f.khan@oracle.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 3 Mar 2026 14:42:20 +0100
X-Gm-Features: AaiRm520pyinVR1ZOFHH1Ic9lRccb4y7w9GFdFD-xIdy5G305nnhw5SJbP9BMW0
Message-ID: <CAG_fn=XrQeLLFWuJx7XCaOKWJu+z3c_7S1mAu3HtP_dmd4xnMA@mail.gmail.com>
Subject: Re: [PATCH] arm64: move early allocation of kfence pool after acpi
 table initialization.
To: Imran Khan <imran.f.khan@oracle.com>
Cc: elver@google.com, dvyukov@google.com, catalin.marinas@arm.com, 
	will@kernel.org, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org, 
	Mark Rutland <mark.rutland@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=sydavu+b;       arc=pass
 (i=1);       spf=pass (google.com: domain of glider@google.com designates
 2607:f8b0:4864:20::f2f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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
X-Rspamd-Queue-Id: E9A181F0863
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TAGGED_FROM(0.00)[bncBCCMH5WKTMGRBYWKTPGQMGQEKMGG4RY];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCVD_COUNT_THREE(0.00)[4];
	TO_DN_SOME(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	HAS_REPLYTO(0.00)[glider@google.com];
	NEURAL_HAM(-0.00)[-0.999];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	RCPT_COUNT_SEVEN(0.00)[9];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,mail-yx1-xb138.google.com:rdns,mail-yx1-xb138.google.com:helo,oracle.com:email]
X-Rspamd-Action: no action

On Thu, Feb 26, 2026 at 3:08=E2=80=AFAM Imran Khan <imran.f.khan@oracle.com=
> wrote:
>
> Currently early allocation of kfence pool (arm64_kfence_alloc_pool) happe=
ns
> before ACPI table parsing (acpi_boot_table_init) and hence the kfence poo=
l
> can overlap with area containing ACPI data.

What happens if another allocation occurs before ACPI table parsing?
Can we enforce that this is impossible?
Shouldn't the firmware somehow tell the kernel that the future BGRT
table should not be used?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DXrQeLLFWuJx7XCaOKWJu%2Bz3c_7S1mAu3HtP_dmd4xnMA%40mail.gmail.com.
