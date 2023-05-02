Return-Path: <kasan-dev+bncBCS2NBWRUIFBBHN6YGRAMGQER2QK5GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 86A216F3B86
	for <lists+kasan-dev@lfdr.de>; Tue,  2 May 2023 02:53:50 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-4ecb00906d0sf1943670e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 17:53:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682988830; cv=pass;
        d=google.com; s=arc-20160816;
        b=is2yIJNoDM9LsRn/MXL7hKYu6AJs90N7dVRavTzKK1QqyH7TbCIyqtB3RugPoZjR84
         JuntCmAAaSrXFkBkKzluOiJ+6QkJHg9GVzbu0IN7BWVVMyzgbqDydLgGIQBO/i3xeMny
         z8CUNk2pgn1tgDb2KyIo02Q4tg8YqI4fePdF3ZIvbUELMW+JBV/swOnDMo0pQ3Mx9FF/
         dE5IWJMHZ1yHxxIK1nHu8Y417Ar/FY6fIHF8V5CgW9cxyTRb20s6wirHClAXdZqTX4F2
         yQsIoiYOJ+2kFnytgexTKPqh3s5or0+eqsBiE/VBAAS0uqFmxF1yG+vQA3TDxuD0eQjw
         lq/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=I3gq0F0Q7rMy57q+h5awPzo3p9XoAZNUHh2tffY4BoI=;
        b=lJmxvcg5qj1BSzSaWT7XvKLHBTG7kSadJi2XRjI2H+Z4rh39xIx9jdvNtBxBUTEVUW
         ZfaiACVZIZYEl5o/dP5MwkN9br1zob00lS4RZoF3AmzuvAP6MmOmYpDF5EeGpoSyo2l/
         sKtCOFmB+8EgLQyU2XTaqRoxG1Jdx1EeNGmi+e+O0CTIaE85lOtNvpAIY4nerOGHbs3i
         JlWPwJlv0twucQ0hO4zf9NXEDL3E0AMYP6ijUfs2niKgQm1O/jR/vJ4S7wGn+sOUyY6M
         /qBAkYj0SaN18Q9e+zSM7/89lTp3j9F3onPVIiQYgtnypMJR4z6ldHSA3ef0Z/hHrzel
         JZ7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ci4cChjL;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::22 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682988830; x=1685580830;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=I3gq0F0Q7rMy57q+h5awPzo3p9XoAZNUHh2tffY4BoI=;
        b=L+ZvbjI7OdLT8j8xqcDytf9vPFRPsflnoCpCTlTUA0vVpey79WpvRmDwc7b3+sSzRW
         Fp64VsbDXRPIo4lSVV0SG5IiS1+rx0csz4GgdU7ieYxtc0kXB7I5f6pvBXEvN/dFkcAS
         zjDvD0KsPjCBwOeBsh29D14jE7yZehkpeXBruzoOoU5LllZqZan8WQHqGYY1weOUguZD
         3R3SDXmX8SbtHJOqiKsMWtvQ/9sPhd7I5NHwnoDFO9HfBPtsqgkG5OQjzCEbj9iB9U7E
         Ds3gXbiFRbcfB5rehsClJW4yxBCUvvldmDS+eZ1RgpCcJkqtDtld+t9y//d6RVTzTE4b
         E1Hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682988830; x=1685580830;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=I3gq0F0Q7rMy57q+h5awPzo3p9XoAZNUHh2tffY4BoI=;
        b=VZeuDtt9+E5JL6KNNkHL1gy46jwuQJVGNP0oKyk94j+QIoUQ6CRDBw81z4mCU/Jdi+
         jZ8LT7HDjnskCP9Dhx3NXZk8Gni71TEnNJaq4OFcCGon1cJ1ed/vzOVN8jwci5V7/TqN
         7I1kcFIpckTamTvSjq2A5C3qeaNMQEgUiWqR/qjG1wX4Kc6His8hzZfZ0vuo1e3cbGFZ
         Z0Anmv9rBL1NaGpoQdx0BlTvsWnlrriOkOyRxYQ/V03eMMmGAyxfQXiwthUAx8P9II/Z
         1prkIQaoO+NgAhF2nnLvI73NlKWR8sl0ApTtu6Oi4+uYZlMqtSkJJ1IGNg2rJi1hiCAZ
         fL3g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDx12fEsjW/xgztQ3QV6oUpvhVTJu6XJ4ZeRJZpUfirmr7d8G35Q
	mrAceqbE3HspWUC60lc0oEQ=
X-Google-Smtp-Source: ACHHUZ7KlipbfOfAMEVPFLqEJcKOzizuWXpCfGZ0sWVn1duCUnnGP7WiKuvhFe0S0lZIPCC4KO63QA==
X-Received: by 2002:a19:5507:0:b0:4ec:867e:482f with SMTP id n7-20020a195507000000b004ec867e482fmr3641827lfe.0.1682988829841;
        Mon, 01 May 2023 17:53:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:b06:b0:2a8:e415:38c7 with SMTP id
 b6-20020a05651c0b0600b002a8e41538c7ls2391618ljr.3.-pod-prod-gmail; Mon, 01
 May 2023 17:53:48 -0700 (PDT)
X-Received: by 2002:a2e:3006:0:b0:28e:a8aa:6f95 with SMTP id w6-20020a2e3006000000b0028ea8aa6f95mr3934660ljw.8.1682988828487;
        Mon, 01 May 2023 17:53:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682988828; cv=none;
        d=google.com; s=arc-20160816;
        b=B2mPwsY92v6O1ws2cqZnGqBigCP1ymKeKWpaaLfzb4LLBi0rjfR0Xi5MvC6bwwJQ3c
         79dc5Ho0m05HfxIwXl5CsG+XL0R7v/DEG8bSsTWLbgmZmRI9lGYfYGCici1vb5+JFE55
         uHWmp77m3RCBxE2gWPGk4WLup1vv4G56dRlOSJ3lhn1T8yWk40q88OBVdCJmN2L6ny2U
         fzJ8qId6f9hwR9M5l6NxO8eN2POIMmekUqan+sb3Y6Am2pDwhyayppt60Gr/wyqenlBg
         9sxgZCyCUrEzNWRArxEGD6sHsoA8pm3xsOGKGRPF8t+ukbL2cuWgVvDEtnmc495kdKDL
         eyqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=HE6/29tmaJsag6zI8A6kmxQ69S3GfTZnUjmZGEHLawo=;
        b=uL8tHz7qyMBBbM00+EYfMtt2vHJZz3oMlf8AkOmRLtOMzMWti3fEiAxPtEJ6XJt97I
         Foi0zOPDsJGCDTYJQhb/PrAg/pffIU33k2CDqYlplwG80M0qkIaEa1q+y3DxsywkfOZV
         uwhw89BoHag+gihkXW5BlFwVG++VydZm0C3jjGrole9i7C6s7wGZjPNon3EBacElZH8Y
         egqmS8D/MnScnsMAGa2QG7e+bvb5rBLt+2JcTv2VyKM2mvjKQXOq/JQojE+tmNpKCOAv
         /iCjliqnY4SnuH5LE+JMESj5yEVwHncBNwq8zgbt55GeTwzOffwEqfprEoyRZOi0embf
         mN0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ci4cChjL;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::22 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-34.mta1.migadu.com (out-34.mta1.migadu.com. [2001:41d0:203:375::22])
        by gmr-mx.google.com with ESMTPS id bz18-20020a05651c0c9200b002a8b4c3cf27si1686868ljb.0.2023.05.01.17.53.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 May 2023 17:53:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::22 as permitted sender) client-ip=2001:41d0:203:375::22;
Date: Mon, 1 May 2023 20:53:35 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Andy Shevchenko <andy.shevchenko@gmail.com>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	keescook@chromium.org, ndesaulniers@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org, Andy Shevchenko <andy@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Paul Mackerras <paulus@samba.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Noralf =?utf-8?B?VHLDr8K/wr1ubmVz?= <noralf@tronnes.org>
Subject: Re: [PATCH 01/40] lib/string_helpers: Drop space in
 string_get_size's output
Message-ID: <ZFBfD96zDCh2RcVN@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
 <20230501165450.15352-2-surenb@google.com>
 <ouuidemyregstrijempvhv357ggp4tgnv6cijhasnungsovokm@jkgvyuyw2fti>
 <ZFAUj+Q+hP7cWs4w@moria.home.lan>
 <CAHp75VeJ_a6j3uweLN5-woSQUtN5u36c2gkoiXhnJa1HXJdoyQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAHp75VeJ_a6j3uweLN5-woSQUtN5u36c2gkoiXhnJa1HXJdoyQ@mail.gmail.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ci4cChjL;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:203:375::22 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Mon, May 01, 2023 at 10:57:07PM +0300, Andy Shevchenko wrote:
> But why do we need that? What's the use case?

It looks like we missed you on the initial CC, here's the use case:
https://lore.kernel.org/linux-fsdevel/ZFAsm0XTqC%2F%2Ff4FP@P9FQF9L96D/T/#mdda814a8c569e2214baa31320912b0ef83432fa9

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFBfD96zDCh2RcVN%40moria.home.lan.
