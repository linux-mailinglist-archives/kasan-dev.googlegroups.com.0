Return-Path: <kasan-dev+bncBC7M5BFO7YCRBDXU4GOAMGQELZLNCAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D66D64B5C7
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Dec 2022 14:11:44 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id i21-20020a056e021d1500b003041b04e3ebsf7299705ila.7
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Dec 2022 05:11:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670937103; cv=pass;
        d=google.com; s=arc-20160816;
        b=gRbt7KnWu6h7g8QljL2MpjGT6ptNkuwrTaabZYONR9SZjLgtGOrzhTHJFE4unczTzD
         CfDbr6W5uwJw5sI71A/Nm/yKQFcfsjl/U80TLBY432j/WK2chvQJW9eRfH/VoyZMR8r/
         eAv8UFolowBRCcMElLBNPYhdU/72fMNPHNuqbFMF6ZlS0zqVqObEdp4t8JfDGFmTXa6j
         yra+k4dzYYav3vZWmYGy8RQusgMIDrVvq6uuoalbjUWRt4+0UJGvaXrjS4AsKSVQQvzr
         N9BcOR49ygnr2s8QLON55fx/jbqwHjVabr6YXKPRMHBq7EwkWJ7Oo6OGJfhM3rI5IXnj
         gNmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=zrb/UdIpqUojKYO9EZlwQuzwInZoNixepBfMK58UGqk=;
        b=PyLY/Z/opdalYIupsiNCDBkA8gW2uF/XlfhuP5Cuv9lY7EmH67uumEcAqSpIlklJjg
         fCWMrBE2qYJVUVAnGXpydvI4xhh39T4iuQePq3nBPNNJVbcVUnqLJasjhgTi/H1RzSKk
         7X4d3bivluuKlgDJsStM3LoKzQRL/3LjQG05ztHO06N3sk6A15bAQ23j6pV21Hg15WCt
         L0UaTcCuG+qBCC7xdCi7XqaQTV4CSDtx9Rkvnwyv/UVDOGL6RBTEfLKH4ll5COUOkceL
         lFs1YG6Ar+xYOfojPeqnvcG4CCrk95FCdVUj0hSpjfPDTums/lH4Im3l8K41eNPK4Q6H
         grrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="huP9rr/H";
       spf=pass (google.com: domain of groeck7@gmail.com designates 2001:4860:4864:20::2a as permitted sender) smtp.mailfrom=groeck7@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zrb/UdIpqUojKYO9EZlwQuzwInZoNixepBfMK58UGqk=;
        b=Ezn1/K9Sg1wMbjZh/JZsRURHDW9C6f0FfFIZdWEwXXm/3p3Vpfafr60Ak5UMh2u5o0
         XSdYVtZbtWedNtFmSsj5dO0oAkbb8ndzJRi0oqaf8Rl2ynaI/geZKWFqIQA6LrUL1dn7
         Xv1J9Bt79dYYCXKi6aKXuBZyg+JmmRtkwm4VTpRNeAqxFuX11pk8+Odu//cMXheB1aty
         wN9p1hxf7TRoZZaUz4zKVKc1Q3TpTaTtayLrAZV3rC0nZJ74VRIiJlta44Rv2lhquhlV
         /rF0HdcPYqsA90r+4T3xWWSi4ctbd7iyKjEEv31T+cFOTcl7F9ihgK20Hy1/GN50n0jb
         /Efg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zrb/UdIpqUojKYO9EZlwQuzwInZoNixepBfMK58UGqk=;
        b=7fDuAPg9y1EYboryuHIppH/gHxQ6SGxvBA0YGMUVfSEnRoMLxIYJ+XxaKBHE5gNAbU
         xAwQozh5UL4oOnX85Z+zRWIWPSeTkyg3D0RZfsW8IZZBofgj5OtW+SfX+1Io5iqew4SS
         Cth+yB+7IikrKvt2nu3etd5xckud7jukWZ7npjhYeENeA2djFJb0wyt5XnD85+6qIMuI
         3gAHqewe/OrDKEMs6oSHRFjDc5C881VLc5gB/PhbhT7Qxd9UhKYAMiCpw6MFmzMp67Cj
         2p1+2lrGKwH4zNBRhYCrCYiXNssNE3z+67fVb5mAaoctDJBEn77+kqZIwweNyzU5LFts
         lPZw==
X-Gm-Message-State: ANoB5pnMKRWFijvkacn/u9e06djPDSkFzslXjM/oDz7pbWHisBXd6FLz
	W+Bj72enspkXfnoukZby1oU=
X-Google-Smtp-Source: AA0mqf6KFRTd5HB1XMkF2UB8c/f1BatT8WVum6lQMBDlwPtTc4r++6xQMwhop9gKj2zHqMWeBC14iQ==
X-Received: by 2002:a92:d84c:0:b0:302:ebf5:7b1c with SMTP id h12-20020a92d84c000000b00302ebf57b1cmr32403106ilq.199.1670937103065;
        Tue, 13 Dec 2022 05:11:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:10c8:b0:302:beaf:a2f5 with SMTP id
 s8-20020a056e0210c800b00302beafa2f5ls3595255ilj.5.-pod-prod-gmail; Tue, 13
 Dec 2022 05:11:42 -0800 (PST)
X-Received: by 2002:a92:cb0f:0:b0:304:af73:f87f with SMTP id s15-20020a92cb0f000000b00304af73f87fmr6117500ilo.16.1670937102394;
        Tue, 13 Dec 2022 05:11:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670937102; cv=none;
        d=google.com; s=arc-20160816;
        b=qYK05zLm6/aDFhHTI24719JumNh2+MOjuezoIRYqHzvUrnBR3mu1wd0L63lfSHQO6f
         offhHU/Rd+NNxy/vsTgu/alhUB7fTpTpXwBwaEHKjbDr0Mgmo51Q0qW/83YymsInI7l/
         bbRw1ROUmJsG4O/q75ZX/ShaWc9j01A/IWgBzI7gU2Fs76Wo65te7cPyUuUo4oQpe4Gz
         NK0gvzpqdymgtUIlEcehVpdpBNyt1IHEn20KujQ0cbwQh4/M6dVnBGaktepdFU/T+G5e
         GzkzSWb1ygw3VQ3oKs9JfYpzOIL9YL585l3WOD6pYfzJ6cYH3XyF8u/0L0Bkee5GYG70
         lNWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=KAw/HCOljVHgj+BBWaxcjEK33owb4M1DkrrbLVmLoWw=;
        b=aJLfTD15XJVrx7MkHI9qx7JXBm9hl+uWYzrQmExJ1Ylb2ALfSwSdJQm2C4F7vnLcOt
         FoIjqXLKLYp5Pdsa0kebNd2JG082fNvk4zpNHYd3ijH97ZpdC2hufHyINhmbhLWbZIrc
         M91ckYTGNhcH/vqTwDQ6Lok2I4URqxkyIl9jjo0HYXfhLUTP/LyQ2EAp/qShdaCzu2xF
         6oeA16xcKJjRnqLFrwqB83gupjt06EWJNYxIK8BzlyBIY3s4TKfjMtNU1gMFDJWlxHlX
         O46KEtb+WMPwjyWPUPhNbVq0ei1PYVZO1sQAVk3tSf/WYwyNL1m9EkD9XJN2oRFOBs+T
         KehA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="huP9rr/H";
       spf=pass (google.com: domain of groeck7@gmail.com designates 2001:4860:4864:20::2a as permitted sender) smtp.mailfrom=groeck7@gmail.com
Received: from mail-oa1-x2a.google.com (mail-oa1-x2a.google.com. [2001:4860:4864:20::2a])
        by gmr-mx.google.com with ESMTPS id z20-20020a029f14000000b0038a5b827993si143911jal.2.2022.12.13.05.11.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Dec 2022 05:11:42 -0800 (PST)
Received-SPF: pass (google.com: domain of groeck7@gmail.com designates 2001:4860:4864:20::2a as permitted sender) client-ip=2001:4860:4864:20::2a;
Received: by mail-oa1-x2a.google.com with SMTP id 586e51a60fabf-144b21f5e5fso12401582fac.12
        for <kasan-dev@googlegroups.com>; Tue, 13 Dec 2022 05:11:42 -0800 (PST)
X-Received: by 2002:a05:6870:6b97:b0:144:8103:8e88 with SMTP id ms23-20020a0568706b9700b0014481038e88mr10411248oab.5.1670937101949;
        Tue, 13 Dec 2022 05:11:41 -0800 (PST)
Received: from server.roeck-us.net ([2600:1700:e321:62f0:329c:23ff:fee3:9d7c])
        by smtp.gmail.com with ESMTPSA id ep41-20020a056870a9a900b001447602267esm1361026oab.41.2022.12.13.05.11.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Dec 2022 05:11:41 -0800 (PST)
Sender: Guenter Roeck <groeck7@gmail.com>
Date: Tue, 13 Dec 2022 05:11:40 -0800
From: Guenter Roeck <linux@roeck-us.net>
To: "Sudip Mukherjee (Codethink)" <sudipm.mukherjee@gmail.com>
Cc: Vlastimil Babka <vbabka@suse.cz>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, Linus Torvalds <torvalds@linux-foundation.org>
Subject: Re: mainline build failure due to e240e53ae0ab ("mm, slub: add
 CONFIG_SLUB_TINY")
Message-ID: <20221213131140.GA3622636@roeck-us.net>
References: <Y5hTTGf/RA2kpqOF@debian>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Y5hTTGf/RA2kpqOF@debian>
X-Original-Sender: linux@roeck-us.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="huP9rr/H";       spf=pass
 (google.com: domain of groeck7@gmail.com designates 2001:4860:4864:20::2a as
 permitted sender) smtp.mailfrom=groeck7@gmail.com
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

On Tue, Dec 13, 2022 at 10:26:20AM +0000, Sudip Mukherjee (Codethink) wrote:
> Hi All,
> 
> The latest mainline kernel branch fails to build xtensa allmodconfig 
> with gcc-11 with the error:
> 
> kernel/kcsan/kcsan_test.c: In function '__report_matches':
> kernel/kcsan/kcsan_test.c:257:1: error: the frame size of 1680 bytes is larger than 1536 bytes [-Werror=frame-larger-than=]
>   257 | }
>       | ^
> 
> git bisect pointed to e240e53ae0ab ("mm, slub: add CONFIG_SLUB_TINY")
> 

In part that is because above commit changes Kconfig dependencies such
that xtensa:allmodconfig actually tries to build kernel/kcsan/kcsan_test.o.
In v6.1, CONFIG_KCSAN_KUNIT_TEST is not enabled for xtensa:allmodconfig.

Downside of the way SLUB_TINY is defined is that it is enabled for all
allmodconfig / allyesconfig builds, which then disables building a lot
of the more sophisticated memory allocation options.

Guenter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221213131140.GA3622636%40roeck-us.net.
