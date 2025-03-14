Return-Path: <kasan-dev+bncBAABBEFT2G7AMGQEKV33R5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8BB41A61646
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Mar 2025 17:30:10 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-43cec217977sf13850925e9.0
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Mar 2025 09:30:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1741969810; cv=pass;
        d=google.com; s=arc-20240605;
        b=SN4dfD0A991eJQc84vrAgbqlP8j4Wjwrv99XYkp+xw+VD3ZKsEN4mrkc98mcX5m10S
         1+mIDv2Cdrr54Tg/dMgMQnsstjP2GCfrxilnCZ51UDVsLnfN+S1v1XBalqafo63gDcxA
         WqFotAFDPsL5ALtBeuhRz5o6BFaM7HIgCqugBlcDooRZBtPhFx05rTM2CliCfWeRVwHa
         DbXah2UObKesou1A8wGuwI4A+WmROZVmvNDYitYNGOIx1nLDR5IZr5iU4Gh5iWONtypy
         FzQhqV4lsPVpT/KMYtTMaBG0mfVhWG2lx+kNQQOrLYqYxcJu0vAjbtTPkqMzS9yYKPy2
         f8JQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:mime-version:date
         :message-id:dkim-signature;
        bh=3NoG5UnLzKpY116Cax8GbEEM3uZJeBRzKt0d+mVftA4=;
        fh=G6+cm5sL3iNSYqavdfgFNuku5RXoqMZT7X2qx4u+QfQ=;
        b=Z6hLv64XWGo2Hetoq45nN9OMBbCGYPBkPvwgWd9KkAomqaQmB30GEqb1DqmbB4GntR
         iDiiQ080Q70kLzRVJGihxIck22QbMqCxrqhepqH6JfYguWKzXj+KTKOhyPKYUuKGhrps
         nWOa97bzrNh9l+VYH3S8nuPYGbndzXN79HF8OtED3QOWvUehPC07+/+SfscXouYhd5mb
         t4wewcOxhhFhsnSHEKvo67ms1DeKjb1Fd6VrzxKFEWXeEyjGVlMQtEw0vJq2o4S3JVH+
         75o2zruKeOdS7faQIdzCo+fvR+8ReGfQV3d32HF5SsuIg3uBLITQcMVCDr7+MsvSFoeQ
         9tnQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@iencinas.com header.s=key1 header.b=pm4irdM4;
       spf=pass (google.com: domain of ignacio@iencinas.com designates 2001:41d0:203:375::bb as permitted sender) smtp.mailfrom=ignacio@iencinas.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=iencinas.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741969810; x=1742574610; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:content-language:references:cc:to:subject
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3NoG5UnLzKpY116Cax8GbEEM3uZJeBRzKt0d+mVftA4=;
        b=a8NVKr35bw/D+0hq+uhsmh490LCCPxWn5j7WIsQOfJHIdBth2x77aU2U+h/aCPrPMC
         oCbQ3QIVAg9JcetxnOuZc6sNJ2nhSNbNUW2WSnay+VfzuIq83XC9XF4Kh1g94iEJDgJc
         aykp1HBIz7QdFDYr9soMp9pUXFj30Go9bn+nDuU8t0tZazE2I4OikWfGiwHVQ7VMQX/T
         v1Sgvvj0EevoYybJrJLp36c1danE2OAYipq9Vlfzr0nBnu89ksNA7CycRHvLpK893X/+
         6NqKOB1Xsmym7EHJt5MEbgCgOevPs1g7bgwG/PeFcSQYldw8OjkrGqv6bP6gY1j8qTxH
         FDEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741969810; x=1742574610;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:content-language:references:cc:to:subject
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=3NoG5UnLzKpY116Cax8GbEEM3uZJeBRzKt0d+mVftA4=;
        b=Iaya52VJdBoJkvkiUhjwbUztVyq0VQFKjbIU6aR3Dw/iI8mSEttp0cD5otV/Y73CBj
         CQApyCK4eslBGg/pNFEwHNvLyIEzQDrmtQcQY9+bnb7qr7q/ujur9Pftp21WpgoAe9WA
         v9KYBeuQ40uMqiqLTYKgI3gPcjvX/2vQH7CVjLYAYsZUUQjT5aLJMyPa+YYyKOS0Tx/l
         FceZl8r3TfhX8PUgZx88Zc6MQKmxYZ2R4vIDefnyWp9B73ul5B3dzLw4AEi+KZf0ahjD
         LX7KGXhMwGIZ6GKdgabFiEWfr9/B9/V2P+OdphWjvdT9DiwUJpne+4royd9lqm3fHsjn
         5X8w==
X-Forwarded-Encrypted: i=2; AJvYcCXPMVmUxlZdjzpigRdz6bNLLk36hDjb+B3TqktelK8RMH0yQCGo/X7GkVE9sZ9TpBdsP62qoQ==@lfdr.de
X-Gm-Message-State: AOJu0YwbliohzdL4b9rppoGCd9Tzl0g+NKBOsB0sVu/rt5U+A/0Cs4zY
	gZGaKJAhdjdLIruihlvR7nzn2lhFMdco+MJacpjLNKJpkkQe2OeT
X-Google-Smtp-Source: AGHT+IF1qqAnp4fTs2EoPksvh741a4P5baA0QaRoJRNvbCwUIUGx2owA75w0Uy6tiSsHU0fHmMiFNw==
X-Received: by 2002:a05:600c:3d8e:b0:43d:224:86b5 with SMTP id 5b1f17b1804b1-43d243888fdmr7242625e9.4.1741969809239;
        Fri, 14 Mar 2025 09:30:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFpAzUNdx5eiT4Dbfd9JxFIakOR1IUvBb98pqppwI4HmA==
Received: by 2002:a05:600c:5116:b0:43c:e3ef:1640 with SMTP id
 5b1f17b1804b1-43d1fb508d9ls6905195e9.0.-pod-prod-04-eu; Fri, 14 Mar 2025
 09:30:07 -0700 (PDT)
X-Received: by 2002:a05:600c:35d2:b0:43c:f3e4:d6f6 with SMTP id 5b1f17b1804b1-43d1ed1af1bmr42921315e9.31.1741969807486;
        Fri, 14 Mar 2025 09:30:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1741969807; cv=none;
        d=google.com; s=arc-20240605;
        b=AiFBfSDc2CigiPy3AEF6CNvEoq2rI48I/iz/54VFe4ftj2ksc20x/+uT0OYmhT5fE+
         SJGPnLB5gkeCRON52jz7RN5J6+vmdhc/TOMYTFSvDqpFypARBmd2uDcgBsJ9y/25QmE/
         /QWoSwqrlvJfpZ7YfDlcGJbOefD8HSuPyOjtrKm6BibRvwBTYcLSfdgrzMYZ83CPJ+tn
         l2gQV2T8AuaNN7IeyDStP5mVgw+8RevUM+WYxwYiYIs28v2Hurly03gHp8JWOSUg5lzD
         NxG0qirtweaJzHS8YgdFIm9ZbPPE9H8ehFnOWtSrlitwv+JjhndGbFMKacyKuI6mZXeK
         VsFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:mime-version:date
         :dkim-signature:message-id;
        bh=Rf3Y2t5DfgJzg/9Slo+edGTDwDk+9738sTXLJVoqKHY=;
        fh=E3ijK1QsCYO9RHiy4+ITC4Sz73dlEs0tf8LJlxPzugw=;
        b=iISjoUz6nOre7+nN2I6q+3mFwKCT+e/uTS5ZlLsVZlNeNdaWhTOji/swQXg/qkL5KC
         yiRSg1AM3XHE858QGBRFEtb5pFOAEQRrgXflZJ7AXGtqAUNRWN0sMRoBbQ0XBYWM+rSZ
         oWMuaHqIJbeH4mBbyJEAwMSEeHnjdUSjcxe0Ih3lXuyI3Nc5KQfoADWz4t/oxLb3crhV
         4OvftLieC90lLsXQl/4N2KxTXhYn3GjoLBNZZjjPCIgSc5lsk+eI7Ur+JhTMVh2+3dx7
         Ax4/eYq2sGI5jP5hzLm6iz1RVb6b5fULtnmRLqzlQgCmfgnhXQ5sKMMltnU4S+mUwdLF
         5NMg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@iencinas.com header.s=key1 header.b=pm4irdM4;
       spf=pass (google.com: domain of ignacio@iencinas.com designates 2001:41d0:203:375::bb as permitted sender) smtp.mailfrom=ignacio@iencinas.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=iencinas.com
Received: from out-187.mta1.migadu.com (out-187.mta1.migadu.com. [2001:41d0:203:375::bb])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43d1fe31a7dsi640375e9.1.2025.03.14.09.30.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 14 Mar 2025 09:30:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of ignacio@iencinas.com designates 2001:41d0:203:375::bb as permitted sender) client-ip=2001:41d0:203:375::bb;
Message-ID: <1d66a62e-faee-4604-9136-f90eddcfa7c0@iencinas.com>
Date: Fri, 14 Mar 2025 17:30:00 +0100
MIME-Version: 1.0
Subject: Re: [PATCH] Documentation: kcsan: fix "Plain Accesses and Data Races"
 URL in kcsan.rst
To: Jonathan Corbet <corbet@lwn.net>, linux-kernel-mentees@lists.linux.dev,
 skhan@linuxfoundation.org, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com, workflows@vger.kernel.org,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org
References: <20250306-fix-plain-access-url-v1-1-9c653800f9e0@iencinas.com>
 <87o6y5lvvg.fsf@trenco.lwn.net>
Content-Language: en-US
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: "'Ignacio Encinas Rubio' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=ignacio@iencinas.com; keydata=
 xjMEZgaZEBYJKwYBBAHaRw8BAQdAYZxeXU5yoeLYkQpvN+eE3wmAF4V0JUzIlpm/DqiSeBnN
 LElnbmFjaW8gRW5jaW5hcyBSdWJpbyA8aWduYWNpb0BpZW5jaW5hcy5jb20+wo8EExYIADcW
 IQSXV5vKYfM26lUMmYnH3J3Ka8TsNgUCZgaZEAUJBaOagAIbAwQLCQgHBRUICQoLBRYCAwEA
 AAoJEMfcncprxOw21F4BAJe+mYh3sIdSvydyDdDXLFqtVkzrFB8PVNSU9eZpvM0mAP9996LA
 N0gyY7Obnc3y59r9jOElOn/5fz5mOEU3nE5lCc44BGYGmRESCisGAQQBl1UBBQEBB0CVC5o6
 qnsTzmmtKY1UWa/GJE53dV/3UPJpZu42p/F0OAMBCAfCfgQYFggAJhYhBJdXm8ph8zbqVQyZ
 icfcncprxOw2BQJmBpkRBQkFo5qAAhsMAAoJEMfcncprxOw2N8ABAPcrkHouJPn2N8HcsL4S
 SVgqxNLVOpsMX9kAYgIMqM0WAQCA40v0iYH1q7QHa2IfgkrBzX2ZLdXdwoxfUr8EY5vtAg==
In-Reply-To: <87o6y5lvvg.fsf@trenco.lwn.net>
Content-Type: text/plain; charset="UTF-8"
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: ignacio@iencinas.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@iencinas.com header.s=key1 header.b=pm4irdM4;       spf=pass
 (google.com: domain of ignacio@iencinas.com designates 2001:41d0:203:375::bb
 as permitted sender) smtp.mailfrom=ignacio@iencinas.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=iencinas.com
X-Original-From: Ignacio Encinas Rubio <ignacio@iencinas.com>
Reply-To: Ignacio Encinas Rubio <ignacio@iencinas.com>
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

On 12/3/25 23:36, Jonathan Corbet wrote:
> It would be best, of course, to get the memory-model documentation
> properly into our built docs...someday...

I hadn't thought about this. If this sentiment is shared by the LKMM
people I would be happy to work on this. Has this ever been
proposed/discussed before?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/1d66a62e-faee-4604-9136-f90eddcfa7c0%40iencinas.com.
