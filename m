Return-Path: <kasan-dev+bncBCSL7B6LWYHBB3EXU7GQMGQEJZYZZKQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id EN4GLvDLqWl+FQEAu9opvQ
	(envelope-from <kasan-dev+bncBCSL7B6LWYHBB3EXU7GQMGQEJZYZZKQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 19:31:12 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A487216F83
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 19:31:12 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-359918118ebsf12017447a91.2
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 10:31:12 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1772735470; cv=pass;
        d=google.com; s=arc-20240605;
        b=WlUCArm8trFyI2sKVawETusFaXq23lV3upjgbeqBMBKkzxX2a/RRDeBhFA6m4XWKX/
         wfa5V/6ZbReMJoQFDSQyoGl3evck38rwKRKn4UxGIi6wtGkm5Xzhlh+FgZYT1LyPzdpr
         z0O5HQXPLhxFcWFQGqD9B8gKe8c+cTnERFrmC0m3oz7s3MDWn+Q3PiKRtk0LYA0r+Jfm
         gpTVgTsR/bdHVZ6N7j9v9f10fVPfTuynbVaLAN9meimwXWuMIqeRQBYsKafZ0OTVzDGy
         OZIs88f9M7gl5twedipDF572veGs42UXrJuSzqXH5xOKP3p9fL2AWnjoEUgjcPvZmd7m
         QlXQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date
         :mime-version:references:in-reply-to:from:sender:dkim-signature
         :dkim-signature;
        bh=9JIvMowjP3PZWBcj72vwTPVFkM9cM3tgONZ+iCjTQro=;
        fh=8fQZGGsaVVnL2haSIyf+KxuRcPeVmaW2SFQmGnWyXEs=;
        b=hA/qHj9WA/u6Vl0mty6OfHW5iGX9/UDv/tee9yprs9NXpm5PfLwhcWQjLr59lcEDUd
         CBLBto4nwMrb8wFoVeGUy4tkzyYGY/CqwJExIfdCACjaecVM6U8ljgLLdDJEEcCFebvJ
         /V7CKbfCcwcWxbm3ku8NTwsQroaQflQpvfITya/2MsKAf9E7jQ03nBi0a3AymFNOsWfm
         kEsQVIRZ7LoMpWXYyUWq4OYth4xZyqa8C4yyQBAUb41kaMG4wnuan1DUe+EUoCNif1i8
         vYJXKSG4Rn4SASgUZYkfXtHDGastLwxJlcd3dWu+eT8/t895eJN5CLhL74w8HIYumNAq
         3FiQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GQK2gaHj;
       arc=pass (i=1);
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2607:f8b0:4864:20::1130 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772735470; x=1773340270; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:mime-version
         :references:in-reply-to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9JIvMowjP3PZWBcj72vwTPVFkM9cM3tgONZ+iCjTQro=;
        b=EL0ZW3WZ9Kf8LRQNrTs9a9sALYKtcuLItSSuBwlI4ht2jtJ4FSkYU9R/IZJeSBZPT3
         uNL91wd/zD+pRfuINUdc4SRUTmN2LQM8L7Dcyn1dUTvWLNUcCY5lVsG1JTqkcaT34aM5
         rL/lGjB5xV8oBbABKF0R+hhNaTv3JDVRkd4AwGfyOcTshIYtwuO2losM9YZ7kc6zAM0k
         lfzCPgjmwvlzV/+AzSf+avnjumbVQiQoijINLoQ0jpK+8Aa/DRhK2Fm9Gri6B2OgYtk1
         T3/jXJIkNSJGqt9PPe0MyAFBlrhajoXZRtlg5MP+/PiIzl2iaEZvRb+ApJwitrG2e2aM
         l0Pw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1772735470; x=1773340270; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:mime-version
         :references:in-reply-to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9JIvMowjP3PZWBcj72vwTPVFkM9cM3tgONZ+iCjTQro=;
        b=kAL5/Z98kUYOXCytKMowLr6GUeElm38Ny7dJL0mtAWUInCDBqVAQBKMdL8w5yKyLlR
         5/E1Lc+svygx2V0L69UqzvzvrjDteuhZZHCHQq85fmgVWPtWoWm6amdLV25OKLjLrRgN
         a7GC2RElip/sFDqEmzsGGeU1OMT7MQgXdKPsb29bMvUmnDOH6XOUEbquhZxFaldsfuNO
         QLnESGHu6XvvGsHUnv2y4oIoCcEvaGvOXlqeaEHjpWZVlAuw0lSwz6sGqd9xbEMWUeQM
         FE6oB9qkb5BpYlbmKARyie7N70cSNpj2VXD5TWxR80Ad8ZpI29vyok4d/v2pBe4guzis
         ZUog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772735470; x=1773340270;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:mime-version:references:in-reply-to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9JIvMowjP3PZWBcj72vwTPVFkM9cM3tgONZ+iCjTQro=;
        b=JblaS4ypovMWGAw11hekoE80NfkdlWB0m1H1RhjadTha78TxEbtJRD4LVM4TECtEU0
         jzp17wkDBlVkfly83noUMLd8+UAJhs2y66BUqrwzvCC3ZUfyc0lmdgDnprh0D08eqg81
         3Jpuy3PTYPbgseXKQq5jhXB8LyN/zlxo3ZoGulMr5W38W84rOwn5y5rH46kwjugoWsio
         Lk91moyOY5yvou91F+D0kMIvmpsfR7+Mq5nNdJcb8j1sKu9O2icpmPfDs76PJCnweCKw
         /xqXry6BqxA/uGxH0xO5wcV34bn1xEqUJvU7HeelWNgNax/pbJwlX430A0spw3XGinib
         3Tsw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCXqkrOZOxQnHVncnYVHhy8TJ9btxdRQLy2kJwa9vHIdswSXpHPWNno/EOtS6nrsByYczSccGA==@lfdr.de
X-Gm-Message-State: AOJu0YxbqNHWDFb7D7HIR7ZXdYZveKT4R7eCyEHzCMIpapzUc6F2BCf5
	zW/G/TSsWIG74IkCG0bM9j1rVjfoXYk1itAlbpdfi/8Oe+h46xyAYSRJ
X-Received: by 2002:a17:90b:3c46:b0:33e:2d0f:479b with SMTP id 98e67ed59e1d1-359a69c0d48mr5972269a91.6.1772735470193;
        Thu, 05 Mar 2026 10:31:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+ER/0vejRhQ0xH4f4t+B2yC8Depc39HBonR59kGBFKEBA=="
Received: by 2002:a17:90a:d995:b0:359:8d38:10ef with SMTP id
 98e67ed59e1d1-359af898346ls961879a91.2.-pod-prod-03-us; Thu, 05 Mar 2026
 10:31:05 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUbsZbvFdR703LfnTaIWkaBwX6uOpITfGrr320x/kWzubgBXPnSmxRMQwJ5y1tpXcWjgLfQEAL8FM0=@googlegroups.com
X-Received: by 2002:a17:90b:3c90:b0:354:a608:30a2 with SMTP id 98e67ed59e1d1-359a6a9f875mr5530928a91.35.1772735465682;
        Thu, 05 Mar 2026 10:31:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772735465; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZCNy+uhWkqRwKii9zlVxrN0gHGmkRLTt5FeobW8cXxMY0MDP1qAfO8heNfoBCFqqbW
         NEKmOhmvb36bmUqVInGiif3ApDE5wQ6GEdE7a/P4EChDaJ5N8E3hjwlAabbvkbpCJxIk
         FdbeVO1WzgVDT91Ve3ulbzJK1FgGET2OXOr8SZ0QpNDFKq8P+jyWP487s0KfLH85KfUN
         3yTrnQCl8GQPC7k0yWDed9l4HZGvGAzfqLg+xGS++2LojaTAq+usCGfCEMDOT4yVp/YL
         66pwDFz+grvpxYmgGklX90GucnLnU3hL3fju3BhRV9DvS9BmJ/D9dfM/iFioC84TjKup
         nQzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:mime-version:references:in-reply-to
         :from:dkim-signature;
        bh=louF0VYT3jVATcdfkHl6P9eqPKqMc0Xl0Ev8Gw/VyXM=;
        fh=y4b9CKqd+jAskBwfYtpXUS1eAqTCV8rr/okuMwWBah8=;
        b=OJ+mqG+VPcZK3QHd7yzga1NklDIgRAIUP5OeTvXebFoD1Lj2kuWJq/O7dNUXfwCuhQ
         ny6dERXmdYUWFPuY/vPyR9WaWHGvUUZ7DOmIEXurQ6K3M+gRWZTinFArBpXxs3R7zT1l
         xCmXTBpchYeDeriXNWmZyeXhOn87g9xzaZNmHLYSDMPv/9IZiyqpVmQpZBtyhd0sId8i
         xlz49aqMhKzeKf4e9ymBf/Ncg5Dv5lOzrJebFlGFlTukIASS47vHy9gsifvEirWiNyaL
         6lucB5tyOT1qdu9/y0lvedNabz5Oqzi4kUw+X6ZJFD5j1+6aHPwyg5WQiY4YUfKXASU4
         JBjQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GQK2gaHj;
       arc=pass (i=1);
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2607:f8b0:4864:20::1130 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yw1-x1130.google.com (mail-yw1-x1130.google.com. [2607:f8b0:4864:20::1130])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-359b2d527a4si68283a91.2.2026.03.05.10.31.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Mar 2026 10:31:05 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2607:f8b0:4864:20::1130 as permitted sender) client-ip=2607:f8b0:4864:20::1130;
Received: by mail-yw1-x1130.google.com with SMTP id 00721157ae682-79852e01cd1so3750787b3.0
        for <kasan-dev@googlegroups.com>; Thu, 05 Mar 2026 10:31:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772735465; cv=none;
        d=google.com; s=arc-20240605;
        b=fGncjBZOzuadV3BOPpbQgavoxgna+NrLrpR0SrrSJkuNUzfWs092Sa+DOpO2KWF6K5
         RluI5nhQ2m/9HAtvXh5nvqDG3HD6uWy0tilL/1OA7Km3RscRP3/CdgQmTrWVzvYdA09u
         zgqs/rb098Nj61LjxSlNS2qBsxeq9wmFVRqX1Cf8NUWmh0LJ9+U9D2u0s2xwyxR5dqEn
         II8/TY1ClCpWJIEjckORhWC6AKE8Wzgt6LU/ynH9C8j4T1OgkA9wOLTqHrhWDRZLc/LR
         XE00qsSXYigFNAtXgG1VCvTCKIBY5ejKn2KA5wXFKnn/8VKZXFVsrwN1eNgJ+lDge9xh
         uNJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:mime-version:references:in-reply-to
         :from:dkim-signature;
        bh=louF0VYT3jVATcdfkHl6P9eqPKqMc0Xl0Ev8Gw/VyXM=;
        fh=y4b9CKqd+jAskBwfYtpXUS1eAqTCV8rr/okuMwWBah8=;
        b=AOi27bLhpmD1dYoaGvmtuKqOD1JgG238I3x/v5Wcg5IekTnP/hF43mv1I8tlFyqLWQ
         63xUkmCGYeOnfPNCFjiy5QD1m75UEZK+pYbgvQjCLeoseDb9RlKm4rY31+/RDNY6jYXz
         /NJb2ZmtR5Yd2SQ6Lh/A1YBmlVANL5t/PLKBt1NU/uWlPKSn1xqytJgKO2j+Qq2oRRY8
         hPeMX6i7upy5Dd9BXcXnXslreIFvYGhsCozwIaEsirP2e9Lur5+twVm7vJ9N3u/anPMt
         toPa2riTLiq1E5yYOyK9DpIF2ITC3F9ybXzkc+CYRbiJyTq4hZr3ZMhyi92p/cW/unDU
         pbLQ==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCWXOfNpICn5NNENhrb+yeQMk8GefK3wSFDy0rjFJPt0WU1OnkN6AIXvF871MF9y/rlrLcPBGItqzx0=@googlegroups.com
X-Gm-Gg: ATEYQzxSBufamUACzZmgknHFbYl1do17PnSWUoVvspTuSaf086egl0hftaqkdFlbMAh
	WnP4lUHr/ne6ZbTpuVolNaCKJtA5NVaDExiGpf0Q2pHnLzVeAMRubTqB8YNkA9ds7McKvFaMtW+
	RAC7XNMyhUIypqGeWTMyHivSxputLqRR0lEXRPHv/7jWhccP1uiwNCJ8MI96TV+kbNOiB9VYg76
	PRkXxoyiaiGb6+hPRhH/jWIm+5VqAJYfyRfEyv9gqBvjUSCc08ie1b4yZle+5daRmJLPuqmQ9/i
	MBqLdA==
X-Received: by 2002:a05:690c:113:b0:794:ce39:c63a with SMTP id
 00721157ae682-798c6b7f74bmr47076567b3.2.1772735464762; Thu, 05 Mar 2026
 10:31:04 -0800 (PST)
Received: from 95991385052 named unknown by gmailapi.google.com with HTTPREST;
 Thu, 5 Mar 2026 12:31:04 -0600
Received: from 95991385052 named unknown by gmailapi.google.com with HTTPREST;
 Thu, 5 Mar 2026 12:31:03 -0600
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <2f9135c7866c6e0d06e960993b8a5674a9ebc7ec.1771938394.git.ritesh.list@gmail.com>
References: <2f9135c7866c6e0d06e960993b8a5674a9ebc7ec.1771938394.git.ritesh.list@gmail.com>
MIME-Version: 1.0
Date: Thu, 5 Mar 2026 12:31:03 -0600
X-Gm-Features: AaiRm52GZ13axMWytXPAWQiFZUnqLmaKbYqKRkeisNV1Nap28ZH-9coEHa7p224
Message-ID: <CAPAsAGxB6RGSYzMq=tjQQmEDu3QP+v_AqmkbWTRyqkk+K35o-w@mail.gmail.com>
Subject: Re: [PATCH v2] mm/kasan: Fix double free for kasan pXds
To: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>, kasan-dev@googlegroups.com
Cc: linux-mm@kvack.org, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, linuxppc-dev@lists.ozlabs.org, 
	stable@vger.kernel.org, Venkat Rao Bagalkote <venkat88@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=GQK2gaHj;       arc=pass
 (i=1);       spf=pass (google.com: domain of ryabinin.a.a@gmail.com
 designates 2607:f8b0:4864:20::1130 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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
X-Rspamd-Queue-Id: 4A487216F83
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[gmail.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601,gmail.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FREEMAIL_CC(0.00)[kvack.org,google.com,gmail.com,arm.com,lists.ozlabs.org,vger.kernel.org,linux.ibm.com];
	TAGGED_FROM(0.00)[bncBCSL7B6LWYHBB3EXU7GQMGQEJZYZZKQ];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_TO(0.00)[gmail.com,googlegroups.com];
	RCVD_TLS_LAST(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+,gmail.com:+];
	MISSING_XM_UA(0.00)[];
	TO_DN_SOME(0.00)[];
	NEURAL_HAM(-0.00)[-0.987];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[ryabininaa@gmail.com,kasan-dev@googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MID_RHS_MATCH_FROMTLD(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	RCPT_COUNT_SEVEN(0.00)[10];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FREEMAIL_FROM(0.00)[gmail.com]
X-Rspamd-Action: no action

"Ritesh Harjani (IBM)" <ritesh.list@gmail.com> writes:

> kasan_free_pxd() assumes the page table is always struct page aligned.
> But that's not always the case for all architectures. E.g. In case of
> powerpc with 64K pagesize, PUD table (of size 4096) comes from slab
> cache named pgtable-2^9. Hence instead of page_to_virt(pxd_page()) let's
> just directly pass the start of the pxd table which is passed as the 1st
> argument.
>
> This fixes the below double free kasan issue seen with PMEM:
>
> radix-mmu: Mapped 0x0000047d10000000-0x0000047f90000000 with 2.00 MiB pages
> ==================================================================
> BUG: KASAN: double-free in kasan_remove_zero_shadow+0x9c4/0xa20
...
>
> Fixes: 0207df4fa1a8 ("kernel/memremap, kasan: make ZONE_DEVICE with work with KASAN")
> Cc: stable@vger.kernel.org
> Reported-by: Venkat Rao Bagalkote <venkat88@linux.ibm.com>
> Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
>

Reviewed-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAPAsAGxB6RGSYzMq%3DtjQQmEDu3QP%2Bv_AqmkbWTRyqkk%2BK35o-w%40mail.gmail.com.
