Return-Path: <kasan-dev+bncBDCPL7WX3MKBB3OJ27BQMGQEY3FN3AA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 27FDEB050D4
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Jul 2025 07:19:43 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-3e0513ec553sf115226735ab.3
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Jul 2025 22:19:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752556781; cv=pass;
        d=google.com; s=arc-20240605;
        b=KpHG5Rrq3OQt3kSlQN8oCO0MZVTZ+dhvP/QeSR67cpUZ+6L9Ns4IdAwhIDcJr6D29x
         6Q0LRnxPA8b2BqK+3SXTXE1bGGRZDIFZDeZjCBywv1hDoEl9yETGovPurj0/LzVTGnFU
         R7ZxHwpogBxFhzCr90ruVztn+A/jt5eoQh+O8y+X+b/kmU5c//OjAS4vtz+lR3lB2SY6
         o9Piv4yy6Q3iYkTVO+q0peOMCYWo6LEB2ShpPB276qXm4hO0bDmrXbToSIPh83EJb4jI
         l0yWPxICSZk2C2kwjh8b+a6m7zEDPyTeBlcM/y/2U51Q4UORLYrVdamPEIoFm+JYmttu
         OIag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=t1L7g141X5jxLJ69XlsePz5wvpUas4EcVlu/0Wi/77o=;
        fh=csLerjWhOQ0Lw7CzwaVUf7KC919QSxHt+qYf9RiXtQI=;
        b=Q2yEOIYxb3Zw1cRFd1OzDsMbE+BDA/q+pU6T3QsWyeZwlW+mDIHgEcf/pFpuocm65O
         JTZfl+7u/rdgrXayIwAiJ3nQvlSnuYNSuttnMrWHB+DAOGmjXHZj0NkQBKRAMGph9LZi
         x7hhRAUoC+xJ8CmkE8ajyBXTq8Afd6CY75XBlL+GcV0UOTQ0XpwkoK+TtEp4Qojskkj/
         YlcoUK+Pe4Zw9+3LOc48/6fnH559A1uSwz1Zl6TFUeLFOTfqwnQMln6g81JzG8Z7ldwW
         Q7V5BIvsYuWsPwwP9gIHh+oD+tXB9PivIEmAG4j6AMWWY67m/+/LDa+XDl91arb1ANcG
         S4NA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="sj/n5ugK";
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752556781; x=1753161581; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=t1L7g141X5jxLJ69XlsePz5wvpUas4EcVlu/0Wi/77o=;
        b=VIaa8A22NDyeRKFf0t52hKI08RLof3Gy7UuV5dCmKXmt76MMmN7ZCMD7Ai3rgvaM59
         Qgjy9Icd02QZX5rJVrd9oF7G4lYD3mE8/h9wsihfeMS9mFTNgqfhhBWNKYhrCop/Ne8G
         66pR1/9lvBgTPGttbmHAn/7FaoEh5V7UxWjyUKHG+fcZ/hm49/vf6hJoYH0KArRTKKsC
         9/9jYIOOUqX+1DDDuxIL7HfIa7xEMYOF5GsrjIuQp8HBW5GVUWBE0kVjA2m3x1cNu2FG
         H0d0/YF91zcF2Y0ugVMD/L740Nm4s7vhP3MKsY5eo9g9BTeHOYTMs579W6izRdtOHT8D
         xUaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752556781; x=1753161581;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=t1L7g141X5jxLJ69XlsePz5wvpUas4EcVlu/0Wi/77o=;
        b=k8+2tmHudoGBKnCCzPGfhZdss5AXRJItmbv7vfaiGrY/kb8XMLQZe6NvSBryDXp5fd
         B0b91KnrjZCWqU2HPmjcQUhCqoVWikFLIX6grwlEd7/r+7x+0sPx/DVTUjE+9Hcx9YWy
         VKNtisHc3CHq3AELDkOz1kCeY2qvYbrdcfdEknrg7sZEsQOjqJc9gbZrj74pk+9WUEZu
         lC/WgDk1nTRZbAmTSxBzqR1gEdhP1U1U7d98Qhk0KWZmAaeIhJLnOZIj4A8dhDznjJBl
         DwtY5uES3+dxCdcCewuNurPjPuQG4WNgVCY7J1pRvB2iX8N7jgivLRHfHQ7FjSvfG/h1
         OlZw==
X-Forwarded-Encrypted: i=2; AJvYcCU0Hxb+kyR9mfNNHfqvnLBPQY3eNE6qVhXbgCxG/eDjbOuS9jtxTQwyW/y2cTtgFSxqCGQSIQ==@lfdr.de
X-Gm-Message-State: AOJu0YzxtDl86HVHjlZWesgVAjH/4b880IkVppyFXAEmYJsD4G+us0BT
	dAwUbeSB9t3oSBcLb2UIYgA6ZMlbQBPBA0hjoM6+NoEjVvBxsNCQSCIs
X-Google-Smtp-Source: AGHT+IH4VgvTRyCKCM0qdLINm1obCEYUA7OCeUvecjAcoF0XnNxqpm3ZWQn0AgAhgvvQAsyFQFSjMQ==
X-Received: by 2002:a05:6e02:2147:b0:3df:2cb4:56cc with SMTP id e9e14a558f8ab-3e2555711admr137756885ab.4.1752556781510;
        Mon, 14 Jul 2025 22:19:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdLwYoDfmpXS9vzwMh6h+kak1ZI4s+zwMwq7q+xKDGgDg==
Received: by 2002:a05:6e02:4602:b0:3e0:5846:49 with SMTP id
 e9e14a558f8ab-3e2440c8648ls43090315ab.1.-pod-prod-01-us; Mon, 14 Jul 2025
 22:19:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXCulWSdACE4sVkYJztAMYR1VvP4k+MbmEad9HAN28DHtczLfflvWFT0D+n77ZsBSUvi+fvYEH7xw8=@googlegroups.com
X-Received: by 2002:a05:6602:6808:b0:875:d589:5b0b with SMTP id ca18e2360f4ac-8797aa2f686mr1603000539f.11.1752556780603;
        Mon, 14 Jul 2025 22:19:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752556780; cv=none;
        d=google.com; s=arc-20240605;
        b=N15jqG6JV5DE1gf7LpFBS9BJZoEvC+M6CAZheQifipS/QhDjsBW5E+ypbF1pL8M5Tu
         Rxhpl5gD6QxOj8mPVPyDw4r6a0rX2vJRSHOLdpYDv9Vu5vgbRHdmhPMItGyF+hpU/6JQ
         lhgzUkCWPO9LYW+7m6Wq1AD6B1Q6i7Yw4uZ33CBgmA7curjgadQw7hTKryquajBHB3/G
         htwmDKOoyTvxew80XUAApxzUN0e7bz6z8g5rhVnKW2NSxpc32819pwPm9qmQLDU/wkAZ
         cX/Cs6YbE5vUdkPJLvVweg+mnom1qNbS9QR9HWE1B27bcLTGqapU8Cc1hhpPvMwlyLDX
         +sVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=L68kgDKZRdzDYwim316c3I3OgGNd6trgCqmbdImQj2o=;
        fh=6I8NmNjnIiHcChegoGrXVOSbt/xrTQbsBopkCpjJ0LU=;
        b=NFyl6ee5XW/ftnjOrBIEMkXzxTlZFqgVP7DPeFxuzk53N5b+HWNTOi+MalSYvIkZou
         HkchoUaRE7X+sOJmDmaUFjOmc6KhAIGGW4UEkN/7tpMa3eFQ3QVZVC+hlMJJgSZVBwuw
         ifo6HLI4tWPnuyDWf0EKPaL50HPbtLGzLHJKkbUGyWtXOwtYcm1CUI9LxjnsgSBqcjx5
         Pv1xBmGLx4Jg4RwtDQtyVJDeDp42uYbeg4oPgXjN6Fc6qH4OJWxgbdI+Hm6JN7X4WOmA
         PcGc4Re3SxHrCuxmLILKSE8tzNbbMCc51wemTqGBEHYipmQSmCmMuU7hAQcgy9tBOMMu
         cQ9Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="sj/n5ugK";
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-8796b7a1288si40860839f.0.2025.07.14.22.19.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Jul 2025 22:19:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id F379E441AF;
	Tue, 15 Jul 2025 05:19:39 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CF659C4CEE3;
	Tue, 15 Jul 2025 05:19:39 +0000 (UTC)
Date: Mon, 14 Jul 2025 22:19:39 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: David Laight <david.laight.linux@gmail.com>,
	Martin Uecker <ma.uecker@gmail.com>,
	Alejandro Colomar <alx@kernel.org>, linux-mm@kvack.org,
	linux-hardening@vger.kernel.org,
	Christopher Bazley <chris.bazley.wg14@gmail.com>,
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Harry Yoo <harry.yoo@oracle.com>,
	Andrew Clayton <andrew@digital-domain.net>,
	Rasmus Villemoes <linux@rasmusvillemoes.dk>,
	Michal Hocko <mhocko@suse.com>, Al Viro <viro@zeniv.linux.org.uk>,
	Sam James <sam@gentoo.org>, Andrew Pinski <pinskia@gmail.com>
Subject: Re: [RFC v5 6/7] sprintf: Add [v]sprintf_array()
Message-ID: <202507142211.F1E0730A@keescook>
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752182685.git.alx@kernel.org>
 <04c1e026a67f1609167e834471d0f2fe977d9cb0.1752182685.git.alx@kernel.org>
 <CAHk-=wiNJQ6dVU8t7oM0sFpSqxyK8JZQXV5NGx7h+AE0PY4kag@mail.gmail.com>
 <28c8689c7976b4755c0b5c2937326b0a3627ebf6.camel@gmail.com>
 <20250711184541.68d770b9@pumpkin>
 <CAHk-=wjC0pAFfMBHKtCLOAcUvLs30PpjKoMfN9aP1-YwD0MZ5Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAHk-=wjC0pAFfMBHKtCLOAcUvLs30PpjKoMfN9aP1-YwD0MZ5Q@mail.gmail.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="sj/n5ugK";       spf=pass
 (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Fri, Jul 11, 2025 at 10:58:56AM -0700, Linus Torvalds wrote:
>         struct seq_buf s;
>         seq_buf_init(&s, buf, szie);

And because some folks didn't like this "declaration that requires a
function call", we even added:

	DECLARE_SEQ_BUF(s, 32);

to do it in 1 line. :P

I would love to see more string handling replaced with seq_buf.

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202507142211.F1E0730A%40keescook.
