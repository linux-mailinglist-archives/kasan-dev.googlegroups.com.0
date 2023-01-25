Return-Path: <kasan-dev+bncBDYYJOE2SAIRBN5OY2PAMGQECOUD6WI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113a.google.com (mail-yw1-x113a.google.com [IPv6:2607:f8b0:4864:20::113a])
	by mail.lfdr.de (Postfix) with ESMTPS id C1CF467BD72
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 21:55:20 +0100 (CET)
Received: by mail-yw1-x113a.google.com with SMTP id 00721157ae682-4fee82718afsf168930227b3.5
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 12:55:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674680119; cv=pass;
        d=google.com; s=arc-20160816;
        b=xDIa0EUj8GD+ISnx2T/Toxcqq/PWguDLoLyodVky6y3eDcku/C+U4hQ3vhOPi76kvn
         W1ZTW1z7VTVWJKgO3gXqjuQW9dwn8o2Hw3sRWSohbFV9Pj3AYPR9kUHlxZ+brHopUAS9
         8EqSJjrJ5PXseSkCO4Iwza5g36/ar3mRzLMaOIBtX39k5KXY8c4Cn8i+MuWtWo1O22Z1
         +wogzXG8DBCEt/VCnkYvmVuB4nTTbjISWHbGI/qbtgQntsOqur3u2o76eHvPNtPPoA1W
         33Qdrhjp4CwhvVHEms4GOWw0mkukFIZj0gc0/V/ArfXDPG4rqRwxY6dbA6Fb7OH+4c11
         0I2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=q31XRjsYrxIJQ56heB0xHoASXVhoBpFyXYMrOjv1szk=;
        b=O0xZskzxN6EkyK/3rYea3MXrjRGfSbq7a8J9TAgDnt7hcA4hS5p/VH9YexVNqpUD/i
         rNH5yJ24EoTRqPAxF7j01hpt7B5ZqFHYM9A+wGrN6nNNI0qLmbf7yoHrcta2NeJpDsVP
         vpVCefRDk6fpQHw3o9md2J0vqCn8DAEgU9DS67qR7j0CF/4N73Zb7dwTPhTd8CQLRfq5
         FkjkMPH+E9R68cZjDbHzjojHuzPxFezsdM5JtnFKK9bBJWI3bdHxog4o0JFjHIleGPEZ
         Y0H+w53bFHnFd1j5lQ5Zhzsj4sWLDEVv2vg5/9Q+OIfAyQscYKm/64aF4v8phcyHMP7F
         YeHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=q1Y43sVB;
       spf=pass (google.com: domain of yuzhao@google.com designates 2607:f8b0:4864:20::e2e as permitted sender) smtp.mailfrom=yuzhao@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=q31XRjsYrxIJQ56heB0xHoASXVhoBpFyXYMrOjv1szk=;
        b=hAZIeRtjfqfCwgcIb22gC4f/WE/4eJM2dXYvxYSDRzwqhrBqMly1Nk3E9KS6hLpSlh
         qV7KbKiO2Txfu9+SKM4CpUcupc+IgYaJFb0Rst9cK+B9dy63BQqFgf4JCVV3dqr+7fhc
         4OROosZq8ubBUFMZNZTM3f4pS/uQWYU4qveuiRL3Zv7S27Ppcds3h1iT118R46jHwRyo
         2l04GKiLFSz44KV6CSsAGatJdRkJ9rcO1y0G/tLEovQVq3PqQLtz9LNPxAMFBdCWvg/a
         kekWlIzLszbZCGUicYs+Jlhc3eHt89pWwrRRA0BeB318I0p1Q2ZKBWoRf5Ov0hM6P+S3
         Jyhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=q31XRjsYrxIJQ56heB0xHoASXVhoBpFyXYMrOjv1szk=;
        b=dS9b/I2dvooT5esgrFeQetakIgPfFpFPpW7nDP3yeNnHtj7WqsOU+a0xHY8LTHzLK7
         Ii+OJO+zBhzyadM06ZcDM9xwbkmchx8bubTf5ha984Nw4ErhA8x1FosYMWMkzBHmkGu9
         dK+cZbEuatnhDbczX/+Bg/kglgPEW5x7C9zxsJAa3E/epW1lIubv3WbH7RaJzTBPo5ZF
         q5MM1W1tOoinT9/IAYW4yLdlHyIecYL2WXD+u+bwluiOuHXVvLyZWtyOz36qixT7aE0R
         +Ls2WA8CTfFhVbJQd6t61o4kfSvueIOyzg2QsSpGVh7LovtztrdJdVnVpD6sdsjksBXT
         HM9g==
X-Gm-Message-State: AO0yUKXke58ijjQFmOpTr7pl/zdnX/fDxQsPidw5p4Uwl5TWf0QhsNL+
	hrCR2ONltz1xTXzMsZ3wXYQ=
X-Google-Smtp-Source: AK7set9+uhAS72RyA6SaOJCy7Duhn9D94XsLLLPFA6pP2tv9O59bx5qbhE05g582cVOvVk8FPDKdzw==
X-Received: by 2002:a25:a2cb:0:b0:80b:5988:2046 with SMTP id c11-20020a25a2cb000000b0080b59882046mr930233ybn.435.1674680119492;
        Wed, 25 Jan 2023 12:55:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:324a:0:b0:803:a6eb:e217 with SMTP id y71-20020a25324a000000b00803a6ebe217ls87008yby.8.-pod-prod-gmail;
 Wed, 25 Jan 2023 12:55:19 -0800 (PST)
X-Received: by 2002:a25:c885:0:b0:6f4:f019:d9c5 with SMTP id y127-20020a25c885000000b006f4f019d9c5mr22011732ybf.56.1674680118921;
        Wed, 25 Jan 2023 12:55:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674680118; cv=none;
        d=google.com; s=arc-20160816;
        b=mVS2DeOqzZ/cBc6HgCQXu32e+spFj8BI4zjB1/i519XSIF6m4f+R2KQuipr/0M0iNR
         r0rL7lXVB3pnIJtilmi+LI++g7Vv0Hqm2TLZLznz1hZR/+w5eyx4WpkI1BO20DSqUJpQ
         31i+YQLPQCQfaK0fQCU9dLoN4EcmthbTbv3RZcjGX7h0D59opVBacr/y82d0rsCUHjfr
         GJpXLixhr+WoV9UCiO0Y7jMUW4mTj/Gsh2BbUruPhJCgdUnTKx652rqadnM6rFF9UZmO
         gYtn68DOUhLRWU2GmHtgG23JmT4JTZQwkpK9fwMp3mbo/iLOKujOsJ0h+H0XwXiyA1O5
         NBkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GW5QetboOjp/W1DGCPKlZRb9/ODQzueiI/Kp5ewpL8w=;
        b=t2W3CcR7YVIlMB43ASHzwIq5lyGp9F9Wy1+UVmV36uSr+XWm5zrYEbng1Hfx23s6tR
         VEXVh1ERVNn94tHuO0s2jMuz03qS5509i0LItUNQI7ZNaQtRLyy8Bl2g9iB0SL8mS73E
         HiVhQQOCn6sveqAsAa+tC1pnkm7ElQNPlQ2SMESs1D9B0OBjnjss2Fw3nw2QWnJzt2T7
         iIMSdt5k1pUEYzMk54WZu8HQZ+OU7UF2+lZsIx0a0UWnrDSkYwe7vmrQgxo9h61EjNAy
         g0Fjt6J4rLBzDe2EhIJi3uOOkyFvsdlidc3y18qXN4RWvvNSaOadZIQlqY6WpXWxo7Tf
         gN3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=q1Y43sVB;
       spf=pass (google.com: domain of yuzhao@google.com designates 2607:f8b0:4864:20::e2e as permitted sender) smtp.mailfrom=yuzhao@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe2e.google.com (mail-vs1-xe2e.google.com. [2607:f8b0:4864:20::e2e])
        by gmr-mx.google.com with ESMTPS id x38-20020a25ace6000000b007b62d9cf791si666490ybd.2.2023.01.25.12.55.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jan 2023 12:55:18 -0800 (PST)
Received-SPF: pass (google.com: domain of yuzhao@google.com designates 2607:f8b0:4864:20::e2e as permitted sender) client-ip=2607:f8b0:4864:20::e2e;
Received: by mail-vs1-xe2e.google.com with SMTP id 187so21046655vsv.10
        for <kasan-dev@googlegroups.com>; Wed, 25 Jan 2023 12:55:18 -0800 (PST)
X-Received: by 2002:a67:f650:0:b0:3d3:db6b:e761 with SMTP id
 u16-20020a67f650000000b003d3db6be761mr4768562vso.46.1674680118522; Wed, 25
 Jan 2023 12:55:18 -0800 (PST)
MIME-Version: 1.0
References: <167467815773.463042.7022545814443036382.stgit@dwillia2-xfh.jf.intel.com>
In-Reply-To: <167467815773.463042.7022545814443036382.stgit@dwillia2-xfh.jf.intel.com>
From: "'Yu Zhao' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 25 Jan 2023 13:54:42 -0700
Message-ID: <CAOUHufashDpjnj=XxaR3jsAxPT6tOuv+Uv9ZuJ_8=vLS_HrDWw@mail.gmail.com>
Subject: Re: [PATCH v2] nvdimm: Support sizeof(struct page) > MAX_STRUCT_PAGE_SIZE
To: Dan Williams <dan.j.williams@intel.com>
Cc: nvdimm@lists.linux.dev, stable@vger.kernel.org, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Jeff Moyer <jmoyer@redhat.com>, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-kernel@vger.kernel.org, gregkh@linuxfoundation.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: yuzhao@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=q1Y43sVB;       spf=pass
 (google.com: domain of yuzhao@google.com designates 2607:f8b0:4864:20::e2e as
 permitted sender) smtp.mailfrom=yuzhao@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Yu Zhao <yuzhao@google.com>
Reply-To: Yu Zhao <yuzhao@google.com>
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

On Wed, Jan 25, 2023 at 1:23 PM Dan Williams <dan.j.williams@intel.com> wrote:
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

Thanks -- that BUILD_BUG_ON() has been a nuisance for some of my debug configs.

Acked-by: Yu Zhao <yuzhao@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAOUHufashDpjnj%3DXxaR3jsAxPT6tOuv%2BUv9ZuJ_8%3DvLS_HrDWw%40mail.gmail.com.
