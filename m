Return-Path: <kasan-dev+bncBAABBGMI6SQAMGQEP6Q3FQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id AF8AB6C7546
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Mar 2023 02:59:54 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id h11-20020a0564020e8b00b004e59d4722a3sf922019eda.6
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Mar 2023 18:59:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679623194; cv=pass;
        d=google.com; s=arc-20160816;
        b=EtvEYUV3puSHmcrEnh4m66jJsAQ0MNupd2u7/YkhXHkXWX7eyxVng/RXLN4yYGDQ3g
         LXcZzQwrt+GcZHdQVmeAEKWi72iwH0fJHczQgcHg4zfs1fSkjcYYEmLg/cCi53SdOGTC
         swxnvv88rOk6S0EwlcbuTE61CI1gxqZM1EEAdzDBbiYLPaxH6ux0E6DZ2a5PJyNsmtMl
         5fXpZmetH7RvLe98BtaOvmiBAUu7aSRLl+nAqYwHYcBsQhu8BCwAiFhqLHMJl+U++DYI
         DjHVSCAqx5+4knZQ6YZ9AeJ0p7CXkbmQ4zVEvvPw8TDtRJ1xn4Lw4sYuQUIMA7kKAyba
         Yp3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id:cc:date
         :in-reply-to:from:subject:mime-version:sender:dkim-signature;
        bh=r5OFi8Z5VQEUPG53+1LFq1S8DYhUwi70mvShTzpjE70=;
        b=pteFJL/DdNlbEGKDkIRMiiVux8+qiW3KDI4qeQLJFRPAEEgP9YXHuawsblTdAndgVM
         +MTk3e6zt2a+Pz5XwQd51Tz7rP05MOzGjtJ8mJE3o7XTtIVMF7R09TMZqxhNpdk+8GdL
         fLz465KEZRPpt6kZ0NEVnFHtLQ3YNriBYkHG+jfe6Asc35wsHI/E//78SfcyEbZCQ+8N
         IvIZsN71jIA3yqBhv7b0sJD2muZVVGP4msG+4mtvEr8N/x3jySByefC2dLwQrrdVFojt
         x9FJkudXC4eJKCM7IdGSQXbhD793pDW1bzUaQagccBBUm8lalivQ0yOBdYnGIjDzG929
         hCpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=lJ4W1xY0;
       spf=pass (google.com: domain of muchun.song@linux.dev designates 2001:41d0:1004:224b::1f as permitted sender) smtp.mailfrom=muchun.song@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679623194;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:references:message-id:cc:date:in-reply-to:from
         :subject:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=r5OFi8Z5VQEUPG53+1LFq1S8DYhUwi70mvShTzpjE70=;
        b=PmXiUjaUpCMN/26ttKrdgJmzxQYc0q8f1xrWx6mGpcMBqh4oTI3w+Xn7QwdqFEHvx5
         H1DocseOl5ZFwQ9itwI/OIK5ssLjo93+O090ZdfqfVGDkJ0GYLnu3bugYUO6/LGy7mAB
         1b0H/xYEGI2CIz/tx698HRutOk4HzhbFg5VVcYgHvoMYo3f5bsmTKWGSLi8BLsDhIT4x
         1gY0jIxchWRycAfwUqr3/j2VXMq67/swSwZ1iLI1jfja0U43PkAZPKJ9xUSXKip84eHX
         fRbViUcTKKURa7sce8yZ5CBovheyLqiSilgA+C9b5p2y/8shC0XZ6399HYsAqqFybPGG
         0Mjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679623194;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:references
         :message-id:cc:date:in-reply-to:from:subject:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=r5OFi8Z5VQEUPG53+1LFq1S8DYhUwi70mvShTzpjE70=;
        b=SxU0wfDi73wlhBlsTZC2ajDknQRW9iAy1oyvwJ4lmZARGrHOLTBQU1xN0worCtMpHX
         gTNgcjV64Wo4LoC+w8IEkJsgiwrP4dgQLvb5rXsb221IULtzz9dP239GGXMO+BG8HnjK
         JPKNnNeHYaXDdt/9PyEV79GTDtvrDdwcIiEj38CUj9IVSuDvJ2mvnwQtlGmrM+PGliUZ
         RihK0xCS59evwLNmA0faa0O1SwMwmvIWal9/2Ha6oU3TGPk0M+F3gve6hspVsWUqf3VI
         j19ej6cCxEy7gPWV8roc0rGp9mkN4Ephloo8gQdPAS4vdxerfEWuz0E6/qr3+zFpsTFe
         HQYQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9fMIs0q51SrIQQD98L2+VPvjIwye/kHnxw7WR/FwqxW/jZUwtYI
	f+3ai1C+tfb2fptpeNAuqaQ=
X-Google-Smtp-Source: AKy350ZVxf5+9oW443NV19OnnpVkBOpEdWGNv3Y8wL8k1RWVQfwufHXeXs2ISRe+fO8+fh+nLgCf2Q==
X-Received: by 2002:a17:907:20bc:b0:92a:581:ac49 with SMTP id pw28-20020a17090720bc00b0092a0581ac49mr491079ejb.3.1679623193954;
        Thu, 23 Mar 2023 18:59:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:510b:b0:4ad:73cb:b525 with SMTP id
 m11-20020a056402510b00b004ad73cbb525ls382658edd.3.-pod-prod-gmail; Thu, 23
 Mar 2023 18:59:52 -0700 (PDT)
X-Received: by 2002:a05:6402:28c:b0:501:cde8:c523 with SMTP id l12-20020a056402028c00b00501cde8c523mr1394716edv.6.1679623192840;
        Thu, 23 Mar 2023 18:59:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679623192; cv=none;
        d=google.com; s=arc-20160816;
        b=AWj/MyoaGvJkdct8pFdERDV7008NOjKeRGmup3wFLA1ZEGPoGTk32nMa1I0sXiBAdJ
         G688jaLxZvefiY+nNvUiVl1ioD3lLR5wkGZCaEPuGz2xdEwLyCOvdL5AIOA4kqPyapze
         fboE4NjWkNxDueYoh8ZGKfaW0mgrLZ8AMP5tLHZa+EJ5HUoRapdbI1sya6tzGD05e7WP
         FPbeX1TRbWHlxGn9TGP334g/G/WlOOO3ireoaR7rfvHo+AZuTsr0joviiVRs7vrXwF63
         ObA0ivVSK1MKmPfLk5j+mOBSBiUBLY3SlnI2M1F/K6tbcJVPTJInW9hZSkmpEDotxqu8
         cQUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=8rhPKrr+KvKxfSIp3VNo6gU3WN6f4iovovmQovzneIQ=;
        b=HH8eHMfIhEWPoj52Ru5U4x8e8eHS4nIG9/qVQQ4mJgLAzakyqxHkA6LXF5AwR43Fob
         1cV98RJQ7UWzAM3LphXO0pgYPyab6gA1nKQ1ce5M78io2PWLJBoHgNJSGTxK0xdmnOIG
         50VzrwrU/42sDaKbRF8DO1IU10DMVi2udpcN0F/1mNhZp1i5OJhcGiy2YsvUkeST1fY6
         cz+wE9ByElPscv9H7wTaP7gNFs+xl9jP2XsBs1jR3H2MUHeqWHbTRF8GGMPg5zoQjzG5
         bz9YmjX36o7RYOO1xScODKeJ3X4abhH7ApiZ2+fuUENBXdGKbzqhcXdn9e3Q5xhLGNJ3
         wXmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=lJ4W1xY0;
       spf=pass (google.com: domain of muchun.song@linux.dev designates 2001:41d0:1004:224b::1f as permitted sender) smtp.mailfrom=muchun.song@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-31.mta0.migadu.com (out-31.mta0.migadu.com. [2001:41d0:1004:224b::1f])
        by gmr-mx.google.com with ESMTPS id g5-20020a056402320500b004bc501f1c76si1109271eda.1.2023.03.23.18.59.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Mar 2023 18:59:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of muchun.song@linux.dev designates 2001:41d0:1004:224b::1f as permitted sender) client-ip=2001:41d0:1004:224b::1f;
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
Subject: Re: [PATCH] mm: kfence: fix handling discontiguous page
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Muchun Song <muchun.song@linux.dev>
In-Reply-To: <20230323151850.e2785b1cff37fba078f26f2b@linux-foundation.org>
Date: Fri, 24 Mar 2023 09:59:16 +0800
Cc: Muchun Song <songmuchun@bytedance.com>,
 glider@google.com,
 elver@google.com,
 dvyukov@google.com,
 jannh@google.com,
 sjpark@amazon.de,
 kasan-dev@googlegroups.com,
 Linux Memory Management List <linux-mm@kvack.org>,
 linux-kernel@vger.kernel.org
Message-Id: <FEB74A1F-9DA2-4B37-8AD5-5E41A399046C@linux.dev>
References: <20230323025003.94447-1-songmuchun@bytedance.com>
 <20230323151850.e2785b1cff37fba078f26f2b@linux-foundation.org>
To: Andrew Morton <akpm@linux-foundation.org>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: muchun.song@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=lJ4W1xY0;       spf=pass
 (google.com: domain of muchun.song@linux.dev designates 2001:41d0:1004:224b::1f
 as permitted sender) smtp.mailfrom=muchun.song@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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



> On Mar 24, 2023, at 06:18, Andrew Morton <akpm@linux-foundation.org> wrote:
> 
> On Thu, 23 Mar 2023 10:50:03 +0800 Muchun Song <songmuchun@bytedance.com> wrote:
> 
>> The struct pages could be discontiguous when the kfence pool is allocated
>> via alloc_contig_pages() with CONFIG_SPARSEMEM and !CONFIG_SPARSEMEM_VMEMMAP.
>> So, the iteration should use nth_page().
> 
> What are the user-visible runtime effects of this flaw?

Set the PG_slab and memcg_data to a arbitrary address (may be not used as a struct
page), so the worst case may corrupt the kernel.

Thanks.

> 
> Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/FEB74A1F-9DA2-4B37-8AD5-5E41A399046C%40linux.dev.
