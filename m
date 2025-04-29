Return-Path: <kasan-dev+bncBDUNBGN3R4KRB74OYPAAMGQEHXXLY5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id A1129AA0BC0
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Apr 2025 14:35:13 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-43d734da1a3sf27634885e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Apr 2025 05:35:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745930113; cv=pass;
        d=google.com; s=arc-20240605;
        b=K2U2Eh8qgnaSYfsX10ZyNo3u+3fmi1h+l9RNfMdc2aDLnxBvfE8dM61c2HybwI5TUz
         lgx3srCZOiwPoo7/5sVvLtwhNUyJUDYja+KB0VRjZwOHaf+jOanAg9aPFD59QdfWcKeO
         ntYrIU5ngxqj15IRXVDhgZ8z/DbAdztIPRGczWZlR+Sx+cS+rTV+FPez0fgt+wY+zlwD
         aVroBAT8hlc5v2VrMT+jdN4DuwHkrjurPdj6zOAXtG5xgxRiPhLHl9mYU6pHfFzelQ+H
         YafSNx0wuwtAMbx4IO/k5JVH9H+anqBbwYiXRheT4695q1ioOsvkQPTyqOZu0qVw+C1b
         YVSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=Y7Ynm736IYWK+1ZexZ8q12OEjA8+FL7D0p0sBTWIcuw=;
        fh=vyvOVj5GCl0xP/rOObD2mBKlzItY3fQJ47mt2USmdhk=;
        b=cZ6vEwWqF8Wqn5RpyJDxELYongQUO0WMDNYStm04qf5jDmVjWRP2nTm42dR7lCCDqq
         eDf+11AJVkzU1KEdcl7n+PAlLP/9w96L52l6s2b5XTfuG02asB/4XzXUJ+rIwvHd7RDh
         03bZX6N5JUpFV9sFi9eW9eDiXegw1PRSYPOmoBh5vlUBDWvOck17bzsv6EiWn36MrcZL
         IYkDuDnJSowpgpECW3zeKxDmfuolhzNvttv/Bu34i0O9Z/o/XPGUTP09QkjFj6unP8fr
         toTqtsoXoI9CGMD65VsZaDALhnCP5GElKg9j0eud6x9e+qlhGWOAnOsZ6mulHl3N8U2f
         PbmA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745930113; x=1746534913; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Y7Ynm736IYWK+1ZexZ8q12OEjA8+FL7D0p0sBTWIcuw=;
        b=a2y9irJf/mfB4110wv6xYW1i93+g6UhxSAVE3Ydrtt7MQB8FmvjoiWSEDxA1WLRrxg
         iwEudFYCvpLmRLEaimrIH/RZyKH77+oDpsp87YnoMEEwIigscWgVP3CAKwrTa3+jUrWM
         uVqFFSBKdo0j09sDRzgTPIRVOrvIOt/dKcqxtVe3y7aR8+PBdb/K+kJGDvE4NffdCDuE
         UoCYm7pxzhgsU3REgubB9w/FozFuiZnP1ahZtZ9/pyd/a1nFQA8gBEVnxLOr1BYFK4iI
         /UDKv0U3FIjM+QjaQABo4bYAVFNyq81YvSDE3K1EaO3LzdRsOuZMPiG/eJiAgfvW4Hm8
         w0cA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745930113; x=1746534913;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=Y7Ynm736IYWK+1ZexZ8q12OEjA8+FL7D0p0sBTWIcuw=;
        b=B3EU/6ry9uUjC/3yzWv5ZqFlyBJ8omvA590ULDzKNiNmJIZDqYaxK4rw2KLSzx1yh1
         XgJXFVvCfKOjy0P1a9PFCyLvHV/diOdjkOZeHvNrlzmLpp2TJx8PVNoYi5lttmICA0Si
         GcoJPpr2EQrq136o9o/uWUO3tfJ1hv9jegTQx7PZjIYQfOTrDPUjs4UmaU7JjS9/sjWL
         0MhCpRuIAjyg5FGxCWxWHQi8u67DoCJjgoBPduKOTzZNMccEKAXnDePsBdU66szSijAw
         qFjasd9wRp6LBMIYkIzFbp9LQILPbUOyFnHyMGz3vKMhhF1KJOWRbHptP7gcHBRTHipr
         kDsA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW8jBE+h2VOdRut5zXlvadwUnJhTzbupGoo6DPn0hBH5VxGujcam2BAklkHSBlxPcINAtZWxQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw57VntaNgD64j51xaBTPZfEhCCY1ZxVV6ZNG6CDHMNKpt3XQlP
	TI3Oj5fNj8ic/hYRK7lDWlnFZ5gBKSeos/B+Q4YpSYWkOGIL4F+Y
X-Google-Smtp-Source: AGHT+IE4sdMqq4Xw5lRduJ9zaKyrXm/XInrdHZEOHudMcYoliSxna8Ebc+DOXb+BcoTAPFY8Ejb+jQ==
X-Received: by 2002:a05:600c:1d8c:b0:43c:f629:66f4 with SMTP id 5b1f17b1804b1-440ab65d133mr122028945e9.0.1745930112083;
        Tue, 29 Apr 2025 05:35:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGiY7FYkDPKr5CY9H0iqKzuV5zJ1kDHWZmEBnafbnfU7Q==
Received: by 2002:a05:600c:3acb:b0:43b:cfb8:a5d7 with SMTP id
 5b1f17b1804b1-44099de315als26275605e9.0.-pod-prod-06-eu; Tue, 29 Apr 2025
 05:35:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUY64JQPlIp9Z1Bm8fA7vp7+CvOFgED794KSD8XbKZGpYq4j5SrbbcaM7UHtdG5n5NakdTMJo0o80w=@googlegroups.com
X-Received: by 2002:a05:600c:3b86:b0:43c:fded:9654 with SMTP id 5b1f17b1804b1-440ab7e9b7emr107261685e9.19.1745930109002;
        Tue, 29 Apr 2025 05:35:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745930108; cv=none;
        d=google.com; s=arc-20240605;
        b=Qzpz7ruJamRj5P/8alqiV5HCzxfLZB6xRlnxAPaBjTpi9PEvNUyo4bbXOrsLabQZTs
         hbVboXQK7yul8o8imbJKkgq0WlGA44NTZuIQkou9mv2TguSn3f4Cn8ixl0nYeSlww1B8
         V6J80K5pUhY1dq+VC3W2OVhAkVERIjuwAzHK2QqezBgjnSDG99JsU5GcvpOEZdweCVX2
         7XCNBkWuujVqdvV3XKwCMhCi9HS1ZwIugiJ4s3oWWobrdLJ33R9c3XrLSS3B6baNWK0A
         pOWiglrhfJB/qh94DOBd+XKJMxXH5dun6SaYL7P+p645NbhQqUMp1JPKVOdc3nFAxtk0
         Khag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=29D5IaLsqqR+/QRublIg6aL3Q1/iCjnRuaX0k6mt24c=;
        fh=UgoJtlxH9ISgjrW4OB9wqy+pyjmp7i9dRM8EbMZecQ4=;
        b=HXvpVC08XjfG0QPPMe0b1ih5wTs/JxzgMdrPSSS45il1L0Xsu1YQSyI0lQGAdG5zYA
         gKJN8AdZLXILIpi1xu0IooMaRVuwJHLBgB5gOOFA7LZVuLllf0aWK4MJul88AH1xXx3n
         SPPgxJAgQdfcBUzAg6zTiGSGROZh4O4oGvHkw7Pk5WzBbFZtgfXhAek1TUA3s5RWvJph
         Ue3oCFh3RlvchlEP/fhv8xNqQz1+pX18MSsKi6qlztLN2aLGsJXtDQBLsDGV8TpF7l2J
         dCPxxDvk5hgY0h8znUQSjcHkEm4BMNDgMPqe9xHIAHOJsjYmTK2Tak8UlXOP2YUssI55
         uZZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
Received: from verein.lst.de (verein.lst.de. [213.95.11.211])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-441ae3f5043si572065e9.1.2025.04.29.05.35.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 29 Apr 2025 05:35:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) client-ip=213.95.11.211;
Received: by verein.lst.de (Postfix, from userid 2407)
	id DBA7F68AA6; Tue, 29 Apr 2025 14:35:04 +0200 (CEST)
Date: Tue, 29 Apr 2025 14:35:04 +0200
From: Christoph Hellwig <hch@lst.de>
To: chenlinxuan@uniontech.com
Cc: Keith Busch <kbusch@kernel.org>, Jens Axboe <axboe@kernel.dk>,
	Christoph Hellwig <hch@lst.de>, Sagi Grimberg <sagi@grimberg.me>,
	Andrew Morton <akpm@linux-foundation.org>,
	Yishai Hadas <yishaih@nvidia.com>, Jason Gunthorpe <jgg@ziepe.ca>,
	Shameer Kolothum <shameerali.kolothum.thodi@huawei.com>,
	Kevin Tian <kevin.tian@intel.com>,
	Alex Williamson <alex.williamson@redhat.com>,
	Peter Huewe <peterhuewe@gmx.de>,
	Jarkko Sakkinen <jarkko@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>,
	Brendan Jackman <jackmanb@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>, Zi Yan <ziy@nvidia.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Peter Zijlstra <peterz@infradead.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Boqun Feng <boqun.feng@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Juergen Gross <jgross@suse.com>,
	Boris Ostrovsky <boris.ostrovsky@oracle.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>, linux-nvme@lists.infradead.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	kvm@vger.kernel.org, virtualization@lists.linux.dev,
	linux-integrity@vger.kernel.org, linux-kbuild@vger.kernel.org,
	llvm@lists.linux.dev, Winston Wen <wentao@uniontech.com>,
	kasan-dev@googlegroups.com, xen-devel@lists.xenproject.org,
	Changbin Du <changbin.du@intel.com>,
	Linus Torvalds <torvalds@linux-foundation.org>
Subject: Re: [PATCH RFC v3 0/8] kernel-hacking: introduce
 CONFIG_NO_AUTO_INLINE
Message-ID: <20250429123504.GA13093@lst.de>
References: <20250429-noautoinline-v3-0-4c49f28ea5b5@uniontech.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250429-noautoinline-v3-0-4c49f28ea5b5@uniontech.com>
User-Agent: Mutt/1.5.17 (2007-11-01)
X-Original-Sender: hch@lst.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted
 sender) smtp.mailfrom=hch@lst.de;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
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

On Tue, Apr 29, 2025 at 12:06:04PM +0800, Chen Linxuan via B4 Relay wrote:
> This series introduces a new kernel configuration option NO_AUTO_INLINE,
> which can be used to disable the automatic inlining of functions.
> 
> This will allow the function tracer to trace more functions
> because it only traces functions that the compiler has not inlined.

This still feels like a bad idea because it is extremely fragile.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250429123504.GA13093%40lst.de.
