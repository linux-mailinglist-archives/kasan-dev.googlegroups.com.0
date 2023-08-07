Return-Path: <kasan-dev+bncBDR7LJOD4ENBBVMKYSTAMGQEIVWXXKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C2C0772836
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Aug 2023 16:53:11 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-1bc44284a2fsf1804995ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Aug 2023 07:53:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691419989; cv=pass;
        d=google.com; s=arc-20160816;
        b=xFMjlWcZ0aSBWHHauWVmQ1q0FgpEQYlv0KfnQUsJoDQnXqE+AvWX+XvI5o9Q+XMtdg
         OfCyUXNlH81khLXCoY1PR72thNrdacvJd9k3AlRKY7DjH3cJNqdNU8lI8gWqfupnEPna
         mOEtOosRO5KSq0zDKCo91SqFocabi7q2y/e6DMQ/YwUaUSNdXerHH4ZTXwKPHkLRspEI
         91nVwuVoJus1vLQ42rI2RXdaiS7sj1baUudqB/5qp23hAj4VXjhV9D7IfXR/N8dBAwbi
         FXq+86KhqWFRw1laRXmbregPo5/L//QLS+KsMFME5m79WUWCLlTywIIDnGH4c1UkCXo6
         S9Cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=gGkPnDNT+ATKCFXwkRy4qmas9ekb4g0Uay4TacRcN9M=;
        fh=ITG3/ENfgy0bHKZaD3JI3Tmt1gGrmgTfaFy5RhgCbio=;
        b=1GEfvCP1FE5j6yVKr1rEZLLT9M0Mdf94UkrHUALVKFRUBrFufBop6o4K78m00lDr8Y
         gpmsLrYKxkycZZSnsKzadM2mKeP4k6XGES6m0ZrejtqumeMxplfynXKqg5BMJ4EFhWsR
         7lmqHJzBzQSDUpV1TW0Ft2rRiMEvLKBNSDdNBFjE+bevHDeiVHajH8yl62+JR3UkfcZE
         Ni+5rmw+yB6q9KzXt2cyvzpVrLwwHqtTQA0UYQKBqhqyBnl51/nXfWMssnueT5OXCTEF
         RAE8nej03Xz4IhXIQQfbzhBcCmOYWfWzQLNlmC/vEAEIQTt+UGYEUeWpwzQZmPksAtl7
         ZbIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=K9lSNwFp;
       spf=pass (google.com: domain of senozhatsky@chromium.org designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=senozhatsky@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691419989; x=1692024789;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gGkPnDNT+ATKCFXwkRy4qmas9ekb4g0Uay4TacRcN9M=;
        b=XYWLZUrRk3PA3W98gpgOIiIp5l21V6l37d0lQ7EinaVV/NM70quPc1AyOOBumdYd6e
         zfdGUPvaTTu7P8r1nWVx9ShzJebGVAo8YOJ4duP2yTco1xxNM6+oApdj3+7/e9Iq0Y95
         t26aeKsDCFZfPQ56hOiPgS5rsdNJHWIswwGYwrMFcYK9AaSEdmn52shw4doWs13ELMqy
         4aUKWkJbAoh8WMDqiP859/aXRMOgpT7nscrsrmDbWKrTlUpxlaBI7j/FjtD4IfTqytbD
         YHtBAkoXoNmk+HiqEcEocJNE+Ju0NwO/YHA11SlVjM45JQ6vj673bDcuex3LsSMz1oGj
         e3LQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691419989; x=1692024789;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gGkPnDNT+ATKCFXwkRy4qmas9ekb4g0Uay4TacRcN9M=;
        b=YXKWC+IQomXocffe8IraybP+mqHmClDSldx241ZBXFGcNq0wEowvP4++g7XCJ/ToCM
         qgwXun78spP+dS0mYQCXgJEu6AvH/jXukEGtmAaWcJyWTidJeQL+3xqxlvd0fYronbTp
         PNhfMdwuEgl687BPV7iX0vuUyXUTrWesA/GLhq61ESUweyOL3otB4fmzyhNjmt+C+pYT
         DBFboRlQ4RhoD25kh6bCNrcFQECOY/wJXfDUOdnhBkhIp9h578QGyiVOuBeyYLo5xMh8
         BBx1AeNop49ohnuU17vGkX/ugS0gvaoLiSQVaS7WGNv5xaQgXYM7eOChMq5vE2YvXze3
         VrCA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwiJsQ4ufX+03CEceBxnBRSyJtigmUCarBjBbgsaLnDeVhNp9Lb
	E8CZzwzzne3d0/8xfjcFNWo=
X-Google-Smtp-Source: AGHT+IHdX9nRBauM5FFirKIry61vM+zdOopNOccOJCjFIqjDCLzUXtGG5BwlgNDTsR8Cu/Yhk2Rdjw==
X-Received: by 2002:a17:902:e892:b0:1b3:db56:9ca9 with SMTP id w18-20020a170902e89200b001b3db569ca9mr319303plg.2.1691419989549;
        Mon, 07 Aug 2023 07:53:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:49cc:0:b0:56c:688e:e115 with SMTP id z195-20020a4a49cc000000b0056c688ee115ls3161457ooa.2.-pod-prod-08-us;
 Mon, 07 Aug 2023 07:53:08 -0700 (PDT)
X-Received: by 2002:a05:6808:128c:b0:3a4:644:b482 with SMTP id a12-20020a056808128c00b003a40644b482mr14478423oiw.52.1691419988764;
        Mon, 07 Aug 2023 07:53:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691419988; cv=none;
        d=google.com; s=arc-20160816;
        b=w1pbeaFbCceMA+9+HyBQD7tgZbffxYWiwsnjbwD8cTvfDv5ab4TJlFg8RbUJRv7QGP
         RFCX5Eq30mcdcOWQDPsBMk1G5OnTixGD5CNfSapARjBlPmW+axbNOvSPmSDGyI/1+2iO
         ylHaJkU77CKhuv77BluWjVFiq3k8+xA+xCRh1JN6S2LCbKhkj3U/uVT30JF+LzYt+U2h
         HsF+zuu+A0ML9h4N/oneNPwqI5rMvflcoeGkkMQeQRdn1q3K3HpVx3YrNi4C0Ny565zs
         9JllFuVkyhvwIT6yQG6R2xpQdQpsQ7knTFfccNnYbEhelJ/FvQXwI27jVwoQS4GddqZJ
         gzpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Mz4C0Ykv3hnD80E1C+XIQNh+DiyZWVyJ/hXfjeRPY3w=;
        fh=ITG3/ENfgy0bHKZaD3JI3Tmt1gGrmgTfaFy5RhgCbio=;
        b=EBUIvOuYDSdDlqgKSLHtr5hiuYAmlWK8jkIPokNzFHWGWTl8s/YTEaLmv6sfFqjvnc
         x/G8cibzWkgdwBNhUYqA/l/MSRqU3+Plk9Ej2ApHuNlVkvbpejOPz4qYS/tQCaeXiwgR
         27ZYsS8y+BaWBTk3Iyyd/hm8kA2tFGpgVHDAPeDq3JR+uaxpUtunUxVcdwM4/EfXu1Om
         9Nm+gHCbiWhzzmjhOCKJ9Kd/kKamrbL2Awei/zU8QOitDIXlsxEvxf6WtwMihi9hACEy
         4yWtrCm2XiqiormcU3VlfZ7WoiVT1KwEaFoT54rONTgm2sqL9qiJyBwla4/qkbgV39Wr
         0Z9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=K9lSNwFp;
       spf=pass (google.com: domain of senozhatsky@chromium.org designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=senozhatsky@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x436.google.com (mail-pf1-x436.google.com. [2607:f8b0:4864:20::436])
        by gmr-mx.google.com with ESMTPS id q25-20020a056808201900b003a772e2f6c0si595857oiw.0.2023.08.07.07.53.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Aug 2023 07:53:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of senozhatsky@chromium.org designates 2607:f8b0:4864:20::436 as permitted sender) client-ip=2607:f8b0:4864:20::436;
Received: by mail-pf1-x436.google.com with SMTP id d2e1a72fcca58-686f8614ce5so4576783b3a.3
        for <kasan-dev@googlegroups.com>; Mon, 07 Aug 2023 07:53:08 -0700 (PDT)
X-Received: by 2002:a05:6a21:3e09:b0:140:61f8:53f3 with SMTP id bk9-20020a056a213e0900b0014061f853f3mr8379628pzc.21.1691419988203;
        Mon, 07 Aug 2023 07:53:08 -0700 (PDT)
Received: from google.com (KD124209188001.ppp-bb.dion.ne.jp. [124.209.188.1])
        by smtp.gmail.com with ESMTPSA id x15-20020a62fb0f000000b00682a27905b9sm6434405pfm.13.2023.08.07.07.53.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Aug 2023 07:53:07 -0700 (PDT)
Date: Mon, 7 Aug 2023 23:53:02 +0900
From: Sergey Senozhatsky <senozhatsky@chromium.org>
To: Petr Mladek <pmladek@suse.com>
Cc: Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	Marco Elver <elver@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	Steven Rostedt <rostedt@goodmis.org>,
	Rasmus Villemoes <linux@rasmusvillemoes.dk>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: Re: [PATCH v2 1/3] lib/vsprintf: Sort headers alphabetically
Message-ID: <20230807145302.GD907732@google.com>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
 <20230805175027.50029-2-andriy.shevchenko@linux.intel.com>
 <ZNEASXq6SNS5oIu1@alley>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZNEASXq6SNS5oIu1@alley>
X-Original-Sender: senozhatsky@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=K9lSNwFp;       spf=pass
 (google.com: domain of senozhatsky@chromium.org designates
 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=senozhatsky@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On (23/08/07 16:31), Petr Mladek wrote:
> 
> I am sorry but I will not accept this patch unless there
> is a wide consensus that this makes sense.

I completely agree with Petr.

I found it a little bit hard to be enthusiastic about
this patch in particular and _probably_ about this series
in general, sorry Andy.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230807145302.GD907732%40google.com.
