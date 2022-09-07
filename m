Return-Path: <kasan-dev+bncBCKMR55PYIGBBO7T4GMAMGQEXHRU4MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63e.google.com (mail-ej1-x63e.google.com [IPv6:2a00:1450:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 628385B023F
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Sep 2022 13:00:12 +0200 (CEST)
Received: by mail-ej1-x63e.google.com with SMTP id nc21-20020a1709071c1500b0076120d57502sf3204310ejc.18
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Sep 2022 04:00:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662548412; cv=pass;
        d=google.com; s=arc-20160816;
        b=AigYe7RStTJd7Lq7PxEfegAXW3zPEe+OQlpZnRX9uVcohR3QyHbGXFlO+ieULYrw++
         hHYyqXqbQi9KSvd3Il2g7TDMmGtP05RFlqrFLwNXM+8tFArbQ1MGe93DaaOs2f+PET3m
         LdfPEsR6Ojvn/zeVvkGw1aECWO+HmzEA0LnJU1TrO449MEMshFKglyR18PBgWVfj7FSQ
         0QQCfjOK7DNgzrIjdjmwbFLvlQrdVbCwV+b243vebecSfNT2VGDMstasGIHwFcJlydTA
         AmWW2LjJynGni8SrGbohxBM+KpyspO9EbAWoFSKBP+M7o577YxmYYYKrAExD5wlzBAPo
         Ockw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=TkkvKmAMJM2F8VE0w4KF4endFPJBPT+hQbv/3MbYkPU=;
        b=daUZP8MgJ1l/DNXvvH4+pcvmkRhAvA3rJgW+tVCKjJFnVBDk71CXqmPYT0JD5tC74D
         91ykfnZEUqCQSKA8OcwXe71k7QascvERCG6KJh1UxC0FOoovoPFdt/nxdKdvu3W8AGHT
         PjFj7txFvNVOa8aCRQXIiRwpkiemqpBtRt9ZjsvGuoWDmEiO2wGocY2q84WdzhFMnjLc
         6FUn7jkjfBs6TtsmdAGpndPEm4dcjgRJ2hQPx+haX0TgMMgk5UvW52QZxl07aU8mWATA
         f5hvaVt4t/zN5GjJKhN2WWD7Ih57for41Q8JhQ+Z4LZa3swCwMHa4HNHe9EfzAoHMMzL
         /tYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=XJuKUxE3;
       spf=pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date;
        bh=TkkvKmAMJM2F8VE0w4KF4endFPJBPT+hQbv/3MbYkPU=;
        b=YzS9IF6A4ESevW201hKj6a+O0bXWvjsgyWXSG+tEus8VJPcmQjwbhOSrUsCNqWbeH1
         MYnXo1IYhs6/VBOhAvqoZ7M+7evIer093QJ6vjQMyPrqcF2ff6SVjBM0lj/KfAKNyc1V
         XsJvaJhwUarD1sHqYkAzUUXzEXG4Kc1ziEeF5HMoeFKVJgZU7XqeTgoq4j2CdtQJ6ieM
         CR7GbBcH49FeRDGb+vByyYYrX+t6whVymUvtrBf2V9+Kwh+cLoPKBhbWrN+6orc/HHar
         juO6kj3AzPHDjnMtw46KmorLXCLG2fu6RHGNamNLO5v3RFWbR45SlIMO3RSIeb6sS/40
         J7jg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date;
        bh=TkkvKmAMJM2F8VE0w4KF4endFPJBPT+hQbv/3MbYkPU=;
        b=6x1t63XC39HdUNst5SV505cOi4JIzpVtMYSqFKejln1MufseucUt8YdcSBhxOqsrvq
         p8KjMSoLwjzREGsNp2MHmoxLVtydN4lUuAsvOgQsHsnzl6uTRBiLB1/cbtKPmUVNy5Zm
         ndmQ7jMnZlKxOHY9TQeS120xUfLXpbhPK9b/azI7ASI/ij78XGqx6z412iSzdUjHkT1E
         YBUwT9gJ9rwDp3J/cliN4HNS0ZYW6KDnzOnT+6aMgzw9ON+FPYNyHl9zX385KiNPiZXv
         OVYq4Iw8DiqVYrYNTS9mcRYn3m2CF6nf58/ZBlR5ihX3kNATRxSblM++ME7Jrn9rMaT3
         vtsw==
X-Gm-Message-State: ACgBeo0kZrJEPxQQ9tKSZ+e2hoIdSQbuZZPo0ITTfAaeG9GEpCx0AkKo
	zfyiO6oRlVVAhTfGWE6x6Wk=
X-Google-Smtp-Source: AA6agR6ob/xYp4eabOvnyWo7XK8Gwo8rpUfcFzazcaPaVWmHIJepci43qZutto2qrozSZHlRDCUtqw==
X-Received: by 2002:a05:6402:11d0:b0:44e:ec42:e0b8 with SMTP id j16-20020a05640211d000b0044eec42e0b8mr2651875edw.131.1662548411972;
        Wed, 07 Sep 2022 04:00:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:6811:b0:76f:ccce:b02f with SMTP id
 k17-20020a170906681100b0076fccceb02fls1778070ejr.5.-pod-prod-gmail; Wed, 07
 Sep 2022 04:00:10 -0700 (PDT)
X-Received: by 2002:a17:907:3e07:b0:741:7db9:eb74 with SMTP id hp7-20020a1709073e0700b007417db9eb74mr1974600ejc.83.1662548410468;
        Wed, 07 Sep 2022 04:00:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662548410; cv=none;
        d=google.com; s=arc-20160816;
        b=KnwKKmtrCHVl3Xr9zEzcu04Q1krpYQpHgEqAjzVzCzeb5/755HiyGKVzqMMcYCiIQz
         1n+v2GjZ9bJcDDMhz3acX4pDzX29Of0+DvuQgGiC32nGg6cpvHnsABEkdDI7I7YNVv0h
         28XE8KCPvkYj+ohbULhHYRcKFbhV6IE5Kr0GO5X+wKgqb4/pucR4abvzmteEazA0xqLU
         4NmZK/8AHUa+15jMhq1sE144zurgGeLE/dGkMUzB5k0idu3qEpzECIJW7BJL9xmVisrf
         6fTVFq2znCEGkqYO2qV1fA/AWREeUwIBfuEhtLJewca/MxdLjHuDs+x9blCIlcQ4uelN
         QWbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=HmaE7iOjn6DeLFkNOLr8ASPOm5MulkrwVeS3GjvYnFQ=;
        b=FDU0X08aKrcJt5fvzn2aODCci7pIa/tfO59peWCD5OBr/lJLlTU136K1k3pzrf3i/R
         NIZPJa0Zy1YVCNsPy3DnfjjQx16zc5Gx4jTCOT+oMbxYtGLo2gd7DcZdk56LnFSAUh0p
         Lp8nz11rmCx0asH8BnyN2PN3EjosYxaLEsZNjz8Oyi7WjQFn6KFoWmgPLHde2uMX24cE
         4G0ppnyNvS3GapzGM6zSClaCGb2KHJdRHrW78w2zGJExWLXlqI9yBbIxsk5xgYZ4Y/qg
         3THRaIzVZJRIFHL9P1Khqk6COBnpmy+uKvtdhN85IIHzSxQpELVwmPLVuQb83swRWwmm
         hU9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=XJuKUxE3;
       spf=pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id hx8-20020a170906846800b0073d9d812170si838204ejc.1.2022.09.07.04.00.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Sep 2022 04:00:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 0A82C2033D;
	Wed,  7 Sep 2022 11:00:10 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id D477413486;
	Wed,  7 Sep 2022 11:00:09 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id +m1RM7l5GGMSVwAAMHmgww
	(envelope-from <mhocko@suse.com>); Wed, 07 Sep 2022 11:00:09 +0000
Date: Wed, 7 Sep 2022 13:00:09 +0200
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Suren Baghdasaryan <surenb@google.com>, Mel Gorman <mgorman@suse.de>,
	Peter Zijlstra <peterz@infradead.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Davidlohr Bueso <dave@stgolabs.net>,
	Matthew Wilcox <willy@infradead.org>,
	"Liam R. Howlett" <liam.howlett@oracle.com>,
	David Vernet <void@manifault.com>,
	Juri Lelli <juri.lelli@redhat.com>,
	Laurent Dufour <ldufour@linux.ibm.com>,
	Peter Xu <peterx@redhat.com>, David Hildenbrand <david@redhat.com>,
	Jens Axboe <axboe@kernel.dk>, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, changbin.du@intel.com,
	ytcoode@gmail.com, Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Benjamin Segall <bsegall@google.com>,
	Daniel Bristot de Oliveira <bristot@redhat.com>,
	Valentin Schneider <vschneid@redhat.com>,
	Christopher Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, 42.hyeyoo@gmail.com,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <songmuchun@bytedance.com>, arnd@arndb.de,
	jbaron@akamai.com, David Rientjes <rientjes@google.com>,
	Minchan Kim <minchan@google.com>,
	Kalesh Singh <kaleshsingh@google.com>,
	kernel-team <kernel-team@android.com>,
	linux-mm <linux-mm@kvack.org>, iommu@lists.linux.dev,
	kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
Message-ID: <Yxh5ueDTAOcwEmCQ@dhcp22.suse.cz>
References: <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <YxBc1xuGbB36f8zC@dhcp22.suse.cz>
 <CAJuCfpGhwPFYdkOLjwwD4ra9JxPqq1T5d1jd41Jy3LJnVnhNdg@mail.gmail.com>
 <YxEE1vOwRPdzKxoq@dhcp22.suse.cz>
 <CAJuCfpHuzJGTA_-m0Jfawc7LgJLt4GztUUY4K9N9-7bFqJuXnw@mail.gmail.com>
 <20220901201502.sn6223bayzwferxv@moria.home.lan>
 <YxW4Ig338d2vQAz3@dhcp22.suse.cz>
 <20220905234649.525vorzx27ybypsn@kmo-framework>
 <Yxb1cxDSyte1Ut/F@dhcp22.suse.cz>
 <20220906182058.iijmpzu4rtxowy37@kmo-framework>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220906182058.iijmpzu4rtxowy37@kmo-framework>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=XJuKUxE3;       spf=pass
 (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as
 permitted sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Michal Hocko <mhocko@suse.com>
Reply-To: Michal Hocko <mhocko@suse.com>
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

On Tue 06-09-22 14:20:58, Kent Overstreet wrote:
[...]
> Otherwise, saying "code has to be maintained" is a little bit like saying water
> is wet, and we're all engineers here, I think we know that :)

Hmm, it seems that further discussion doesn't really make much sense
here. I know how to use my time better.
-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yxh5ueDTAOcwEmCQ%40dhcp22.suse.cz.
