Return-Path: <kasan-dev+bncBCT4XGV33UIBBTNA6OQAMGQEMLYIOSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x938.google.com (mail-ua1-x938.google.com [IPv6:2607:f8b0:4864:20::938])
	by mail.lfdr.de (Postfix) with ESMTPS id AD0686C72E7
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Mar 2023 23:18:54 +0100 (CET)
Received: by mail-ua1-x938.google.com with SMTP id c18-20020ab030d2000000b00751d7bbfb13sf125341uam.4
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Mar 2023 15:18:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679609933; cv=pass;
        d=google.com; s=arc-20160816;
        b=ytmpXr3r3ywZeZOMTGEFHaa8ipJYQ4IYEDX7vgD7Q5A39DbNFfSQj/9TRsKVTxCM0c
         vPeyF+wKxWpjvXvYP/0fODUfbxNhc7xZgwRR49RM7ztOj84empVkAwcyxKCj6e2BCpig
         KCKItcumTsuOaa+ZvdyPx6r8rPjPSMvLDnyhG+CxCL317Muxnuc6Ay1jma7StSAaO1w+
         +njJFFC5XrWwLGw6hlORChasYamuu/0C499ZgbtMH+jp79UBl670PU9TxCjwC54k3ZEi
         XRejslL+nAR3ttFvgQc/bV2CN8dErQNVTEahhnbTqI8OY9ak45OR1bDRn7KDrS0D5YSJ
         iCDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=fk1P6OLLJXsctXwDk6cdE8L+1CXdXk2YvUiwsvOnB6c=;
        b=aZCLSCSX+GjiMObco9rVoxCwg5tFrNP6CjD8mRnR7ABOVAXaNtFLrbqB1UkZkbEvaW
         cmGyQFAIojF+WTY9e6bv5Eo+aY5UGrposUM6hPPLthoKgsyi5WVq4Yc/Rcwk6w0ys4kD
         kvkmrIQo57il7n3TtnRaIVLiZ0PJZAylQ8KYDEE8i3ZENZ6ysGhxg97vgf+raq8O1RDs
         W0n28b6LOI+xL3t1HbGJIvzzSke1fan4Z+vyJgtUeDApGe5zIGHefW9KSJQ/t9FsQr3Z
         DLWEinTlimBne2iNYPKVaPoYJ1YRmC/kc7SBK2rPpuDmRbtiX2nYBYNe3Y1SCnnNt4OR
         b0cA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=kOBgCgRc;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679609933;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fk1P6OLLJXsctXwDk6cdE8L+1CXdXk2YvUiwsvOnB6c=;
        b=Vm+Cj6mzpkU3aSNSAxaZpJ1gaC+tgNN0Z3hYLMh/0xAueBDPbr1PDaR66ydDjrk8zQ
         J6dW8x6STrlSaqkwXBEPGCxl2g3WQrAXE3n65E3kOxz2Wm2WhK4dP60qmYYuM7duepp1
         3uB5IE0G5PWa8+JObLegdM+dMWy1JTgiw2MBGn7mZR1kazBEtcHU4ywrqprlCnYpevSK
         OcXhD1UkgtwM6KDzIobAbYL8YjaLh00s9HCaiRfXooIJFcWJNUyW4Dx/4Fde1Ft0f5At
         FVfNpGN+Ha4kZN07L3mareDpK+H0ESspw6Aa+yUYHcGAQQVkor3djnBXD9hLU9zyYuKr
         bu7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679609933;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fk1P6OLLJXsctXwDk6cdE8L+1CXdXk2YvUiwsvOnB6c=;
        b=LxAR0oZnEqDlJiAGVXZYSxUuDQj+WnAXHBj5cGX+wWTMKvKqlZ80yHUsstwldLXsBV
         qM9IpuR4a+lIavE0i7aNVg2OvVrsy6Phin1vcgyLo9a7ebP87UTWJAqZXW4b6pMXXDco
         Y4IR+ZROfq0kqS7pyvc+Ik1j36i/d5MuaBMVulLlNpWCpeEGl0mneJ3rmxSiKsBNlo4D
         XCTX/YKI7eQHiKi57e9lhO38W8kv5pU2oRGpOAT2BQ7McNKK0MOyXiaroM/QNfHJHFbX
         pXSx9ChGWeUzhu37E61ACq6js+UOrIt+BRlKQrEjwa/SL6Bq2fsfdaOzttkZbEXZp6je
         7x3w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9ctcgAcepBmnaCMKbiL+wn0Q5PhDpOxtXgx56cDiw1eo0UuxlUz
	IWvwmhof7ymBAhFrj23eUZc=
X-Google-Smtp-Source: AKy350YFW9kpwD26fAzjKogVWY6oPVp0DUlIiEoiXcOcRJHxDczyhx/QbD6DSSyyTHDvulhwv84MnA==
X-Received: by 2002:ab0:3d9e:0:b0:764:793a:6618 with SMTP id l30-20020ab03d9e000000b00764793a6618mr158051uac.1.1679609933345;
        Thu, 23 Mar 2023 15:18:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:3ec2:b0:423:e5f9:19c6 with SMTP id
 n2-20020a0561023ec200b00423e5f919c6ls489031vsv.10.-pod-prod-gmail; Thu, 23
 Mar 2023 15:18:52 -0700 (PDT)
X-Received: by 2002:a67:ed04:0:b0:3f7:c15d:f18b with SMTP id l4-20020a67ed04000000b003f7c15df18bmr233223vsp.3.1679609932602;
        Thu, 23 Mar 2023 15:18:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679609932; cv=none;
        d=google.com; s=arc-20160816;
        b=qS5RBeZ0vnyzyimTdMV33DgoINTNddcw6Zg1bQRydZ9W+6NBvRrkCWZmITSERpEd0L
         iQhwl47BPPMm58pT0lrjjy+5XkQdhnhiFFyggyykOIH7Gb0TJtZ+IF8+doSEZKJXTOY9
         QZfQ8dJVLZ2+YNam1xf5YPk+juIYh+XFnkdZpUmc16PQ7C8aOhvprLZ8dd2vOv4Gh7fx
         RRkuKJWMn7juS+RD3RoGttoWmrIt+y1NM+wbb/3eLoiSdWsTmBAt24JVMCqp6x3kDEAX
         MkP3yR9YsKLocB4KtwjH4FaHS7r6F0o18NfWNdPGkaQgYNH1LdghuKPKpPO7UExPRRdw
         qz0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=O4Ru8fyq2qUax/RXRkWJCuIYSsBuJuIiR89K5Axpcu4=;
        b=da65a0mG4EoQsdzBxjs6BYvO0BrgNUAGN8jGJZWSQ/Ezsv0aJ0djdVCRMyeuODK2K/
         fWmEUuuvW/VRhDkHLlyntB40cjB517XfYtaywdXGNhxe9d9ZEstZsS2bp8P/Vw57khOo
         iwUtMIOIMjxI60ijHVXhpxW+0iJbxN2i+oYAKD0YGx4eTAuAw8zgmYRQ4xwTPVtcMgQq
         6j+/dux10hoTb9BwcE4wb5ufPXqFPw5sw4d8bOT5N39OMy5tlt+gfS2e8Jn3uVQchzlv
         sMVkuBsv4Apl0XtM+yb8t01V34KXLIstBm0Pkjk83a6wIkPWX8ky3ZeZK59VFCSJXC7N
         atYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=kOBgCgRc;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id ba16-20020a056130041000b006903d74ecf9si1782222uab.0.2023.03.23.15.18.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 23 Mar 2023 15:18:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 1D57762875;
	Thu, 23 Mar 2023 22:18:52 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 28F79C433EF;
	Thu, 23 Mar 2023 22:18:51 +0000 (UTC)
Date: Thu, 23 Mar 2023 15:18:50 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Muchun Song <songmuchun@bytedance.com>
Cc: glider@google.com, elver@google.com, dvyukov@google.com,
 jannh@google.com, sjpark@amazon.de, muchun.song@linux.dev,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
Subject: Re: [PATCH] mm: kfence: fix handling discontiguous page
Message-Id: <20230323151850.e2785b1cff37fba078f26f2b@linux-foundation.org>
In-Reply-To: <20230323025003.94447-1-songmuchun@bytedance.com>
References: <20230323025003.94447-1-songmuchun@bytedance.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=kOBgCgRc;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu, 23 Mar 2023 10:50:03 +0800 Muchun Song <songmuchun@bytedance.com> wrote:

> The struct pages could be discontiguous when the kfence pool is allocated
> via alloc_contig_pages() with CONFIG_SPARSEMEM and !CONFIG_SPARSEMEM_VMEMMAP.
> So, the iteration should use nth_page().

What are the user-visible runtime effects of this flaw?

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230323151850.e2785b1cff37fba078f26f2b%40linux-foundation.org.
