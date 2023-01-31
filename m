Return-Path: <kasan-dev+bncBCCMH5WKTMGRBPXB4SPAMGQETKRR55Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 67538683121
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 16:16:16 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id nb8-20020a17090b35c800b0022bb3fd0718sf6138328pjb.4
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 07:16:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675178175; cv=pass;
        d=google.com; s=arc-20160816;
        b=SUaSSIMwhlJYBuD+IIEuuzb/jFGRgGrKLkUyBpOKKPqCvmLTEMGPHXJypuKL/6oyNP
         UfGddR78mcc89ixAtTKtaPwmJxTH0o3hd8KSehVXWiW9azj18nELY7gQDSXPqOXz1vbX
         I+QAgULVh5eg0wyfQ4tdQPdrFIFNEkEuWfN25I9vE/Mv4UeqdF/2vDIS/malodUE5/qA
         +sCCPnqeqTH/x1oKWGMC2TV7n7JnTvdLrV7JwhiMJXKh2ilcP0BLx0NR4RdNUEJHAvK2
         HolQzl96zI9ZLRo48gDzJ9UFixMQSj73p7dO3Wf8kILDaNyIQk8UWmOaXuFQXa9jBIYw
         61Ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DEYX5fAimXrYHMw6FqsAaetKcJRJF9vfhiGL8GiEyCI=;
        b=Lvtz9wH2pPv92lNu49hPMuGeejN1WTvBRK8/pIPMtvf4cOz+kZ+16O0qpDKuSKxtPG
         xPTCLCEGLbKKDrGh/D/IcmVQlvb/VfXZfW0zQrD7fBc6J+iFB1EeWcBb2TV8uH2DpnRd
         qexRVdR2uDwtFOz9Svv1qDtMx5wMRB7a4m7yWSyL13B1BOlR6ygzX2vOIcoCxfkanWgw
         uRA7WgLd2KrASyCX58FBjGoPeYF9r+QSf9PizXShXkoWfbfX2aAeepGnNKq47J7R1QBQ
         4q0nvLNqRoH51rVisiRMvTE4M8AW07AlGgFl9IEQsc5Kn/BnvGgqfBFSWdt9Qsb60JHb
         hX7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="JtZQ/lBm";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DEYX5fAimXrYHMw6FqsAaetKcJRJF9vfhiGL8GiEyCI=;
        b=ID4Y6iu2WG6y7A+TFYnedtKnG2OzqUZoocIelAUcSzfRRWt/sBhFW//Z5OA2zjSx8t
         /QOaxjD2y+tkKLZXSDonSvCzZkXOFOAuey27NK3g5jupLuDr71Ch1ZlhrM4eLPg9Vtd1
         2uJY/ZLGsNejwJmPDz4n9/PG7W4GqtED1d3BTJg13BaP1M8sfLNjM1m7S3NexKya5Vif
         mZMVAKd+igJTL+vicYnHaJCO1QN+YPggzQjUJYARzU55zcXqun1EDGGrjBD1E1nZe7Ti
         HMcMURifSSUkgEEjtyvUSry3I1cVkmsZAfCnvd6evJzwuXFje1Hdbm+taehLplntzobv
         M0CQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=DEYX5fAimXrYHMw6FqsAaetKcJRJF9vfhiGL8GiEyCI=;
        b=7z/4Bks5t6n7d4LXzJ5vBNFbJHrKqpXtQVdI0n9yf+LerQzWu5MBN8y5cz0TJltPFr
         FlIuQInZ4Tc6U/0OdakOYSMJ7AjLKX0C/4FJ/SELJRLdEvsbtECheLLrkYK4o3y6Ntao
         kglXvZNveTOTHeDUGBs7IpHe9Eug+x50GehU8jWchIwZ84LALh/GNvIFCKVpj20cvlVk
         v8misFo+PXeBiPQb09H3nP5tQkjaRoe6FgfTYU4rtLXjQtLN3KG+qEbu4RSAOjTxtsUO
         Dy1Zd5EBhVN4koY64rBzAp47/9NxVTMYFbtckoow9JtF6iJ4gtHDTP+q0bGrGXspH954
         qmyw==
X-Gm-Message-State: AO0yUKUR4vJFIOYhnOGKphLXbayeF0nErxuwkoUbna0hrbK2dqGu+7Dv
	sQM2P14wHmdhTJxB75yaiRQ=
X-Google-Smtp-Source: AK7set8g4gl+/rsuTnwWSIRe8IyrsNEM8sVyZMn1w7hFwLq7DGZMV6V+QrzNXFN2qEBUOOHolbF05A==
X-Received: by 2002:a17:90a:fb85:b0:22c:5e3:1476 with SMTP id cp5-20020a17090afb8500b0022c05e31476mr3938766pjb.111.1675178174899;
        Tue, 31 Jan 2023 07:16:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a3c2:b0:192:62df:a3e7 with SMTP id
 q2-20020a170902a3c200b0019262dfa3e7ls16743683plb.9.-pod-prod-gmail; Tue, 31
 Jan 2023 07:16:14 -0800 (PST)
X-Received: by 2002:a17:90a:19c2:b0:22c:7603:3793 with SMTP id 2-20020a17090a19c200b0022c76033793mr11762369pjj.20.1675178174157;
        Tue, 31 Jan 2023 07:16:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675178174; cv=none;
        d=google.com; s=arc-20160816;
        b=fNfyCr9PA0hhSaKN3EEpUiWNA/2cWRgcodBvb99SymIzE0MLbPJt4bJzSLXJmi1TrY
         z3ZB/zCgvaQOBeih4ftDma8GwQvPBq0wrGrzmkGZsey/o8x7MH0Vn9hdPLvcHJz0e44T
         zkw8vCZ5+zDWczWSv6WVEKS6CkFVUkxo1PJvQcSjwq2QgwSZY5THbxJ3mosXKfojnn6s
         TWinmkO60X0/ne2DxF3NHQLXUkrKLMryYN+LOUVZrHDcDjtRn2P8gG3C5Nb3sCL6/Gxk
         6PsCIa5F+AsqwBcEojQjGm4Q6nWK9REKtTdvn3jFZzubHuH5vlNQZZNWGEJBM3ftOus7
         onxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hqSkLxxkS4WxXckkEqwqJ2FoqZVZdDRCF2SZ/0LGP88=;
        b=ngM6KCNfWwVGqBJMziIlfxiPL0J6yQs/sY2JHonNcRiByaNsQGFdrzT6q5TEqLscXT
         WrkfgrtsnCwDn93S4ktbTwABfcDdqXDjus/c2uiuluRLch8ioZNg8y2W1G1Pv66IDTZg
         wNcTVYoAQevElnXCjRGM1xqjIUa0P9AZKmstf0HlCvBSb72saMoBJrRjxh0ij0mmpNdN
         GUJOJbd2xL4rJq7ETB8QFwStTWC7HU6U/u0Ib1wbqCasUp2XAjlfA1PZVZhaT2o/Colg
         43mWroQadYvd40Se06sxJ+ilS4PuYDcwwDrR0Mk+dfqQo6825Kvc17jpEAMzzxAHLjRU
         2upQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="JtZQ/lBm";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe2a.google.com (mail-vs1-xe2a.google.com. [2607:f8b0:4864:20::e2a])
        by gmr-mx.google.com with ESMTPS id x8-20020a17090aca0800b00229b4d7172fsi1078042pjt.3.2023.01.31.07.16.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 Jan 2023 07:16:14 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e2a as permitted sender) client-ip=2607:f8b0:4864:20::e2a;
Received: by mail-vs1-xe2a.google.com with SMTP id j7so16338529vsl.11
        for <kasan-dev@googlegroups.com>; Tue, 31 Jan 2023 07:16:14 -0800 (PST)
X-Received: by 2002:a67:c31e:0:b0:3ed:1e92:a87f with SMTP id
 r30-20020a67c31e000000b003ed1e92a87fmr2427528vsj.1.1675178173210; Tue, 31 Jan
 2023 07:16:13 -0800 (PST)
MIME-Version: 1.0
References: <167467815773.463042.7022545814443036382.stgit@dwillia2-xfh.jf.intel.com>
In-Reply-To: <167467815773.463042.7022545814443036382.stgit@dwillia2-xfh.jf.intel.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 31 Jan 2023 16:15:36 +0100
Message-ID: <CAG_fn=U37EVEYYBTRWvOzVq7n0sSqaS5UN-9pjfZQnczAv3B4w@mail.gmail.com>
Subject: Re: [PATCH v2] nvdimm: Support sizeof(struct page) > MAX_STRUCT_PAGE_SIZE
To: Dan Williams <dan.j.williams@intel.com>
Cc: nvdimm@lists.linux.dev, stable@vger.kernel.org, 
	Marco Elver <elver@google.com>, Jeff Moyer <jmoyer@redhat.com>, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-kernel@vger.kernel.org, gregkh@linuxfoundation.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="JtZQ/lBm";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e2a as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Wed, Jan 25, 2023 at 9:23 PM Dan Williams <dan.j.williams@intel.com> wrote:
>
> Commit 6e9f05dc66f9 ("libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE")
>
> ...updated MAX_STRUCT_PAGE_SIZE to account for sizeof(struct page)
> potentially doubling in the case of CONFIG_KMSAN=y. Unfortunately this
> doubles the amount of capacity stolen from user addressable capacity for
> everyone, regardless of whether they are using the debug option. Revert
> that change, mandate that MAX_STRUCT_PAGE_SIZE never exceed 64, but
> allow for debug scenarios to proceed with creating debug sized page maps
> with a compile option to support debug scenarios.
>
> Note that this only applies to cases where the page map is permanent,
> i.e. stored in a reservation of the pmem itself ("--map=dev" in "ndctl
> create-namespace" terms). For the "--map=mem" case, since the allocation
> is ephemeral for the lifespan of the namespace, there are no explicit
> restriction. However, the implicit restriction, of having enough
> available "System RAM" to store the page map for the typically large
> pmem, still applies.
>
> Fixes: 6e9f05dc66f9 ("libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE")
> Cc: <stable@vger.kernel.org>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Marco Elver <elver@google.com>
> Reported-by: Jeff Moyer <jmoyer@redhat.com>
Acked-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DU37EVEYYBTRWvOzVq7n0sSqaS5UN-9pjfZQnczAv3B4w%40mail.gmail.com.
