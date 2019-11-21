Return-Path: <kasan-dev+bncBC5L5P75YUERBHU43TXAKGQEHWYXDTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 396A4105C92
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 23:22:23 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id w1sf1304784lfc.8
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 14:22:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574374942; cv=pass;
        d=google.com; s=arc-20160816;
        b=u3qErEtUE47G/JdkA+6DPh/zyLidWtq2YqxEE4fC50hPtGDQqb9jE9ibDErBLVNx68
         DhqBnxJG05F5OHZ7+IAXxBfTYtSH+VwaPmY68Ke8dRDL5sRCsH0KY8WiyPN0FgKTsP0i
         RSp3cIAwXz3acc/8cYE8nPFOT+5ucNyDGXCz+mogeYXwgRle7oG7g/yuOu7pub8VuZDL
         q7J6W20VuT/ZSwzLhqppxNUrZpYtGMwaqzCIEwLHmwE3qdU0f9bPm1VqxX/+BKJYI9c6
         MHQuynanQHjM9G1ckLRWEfr5lHt/OyuZWex48YWyVeAcD4ESgNjMpDjUoghjjg8swOo3
         A5jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=m0vRc1sId1C2WIrhVfMM1dqLPpNNRKy6Bf2LlVl4icg=;
        b=N0xnzXU2gyEAKI1qc0wEJpG5tMJP4G5s77+shzfwYX5SHzHSn2ktEv5YFbgGm81VlZ
         8cMwsdAQkNZzYStMDU4KRg8UA5vx5PtP6HcY8T/r9Y+0jK7thX+Xuhp22tDxz9varPPt
         27KLWGR6crlEcKMXRELEqKobLZDfDvLEOqNToFfIMbKFabvxJNlcG7Yx5w1NTg+phcHR
         XS+Q1tqr60US1wLX+Gd4QJPyMndHQiojgYt6I5ycrXeiEvz2i4cEikQl56JWeJWuZhGz
         7IwJA4gcOOozVLL1E2+de7HCqFVxfdy5/VuJraTZqJ7X2JV3s+0HhqgvP7ad8U+b70Vr
         8MRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=m0vRc1sId1C2WIrhVfMM1dqLPpNNRKy6Bf2LlVl4icg=;
        b=J18Ich/3vg3/EB0Aaoq+uqKtTunfj/2ByA6UGrPwGe/fKWaHREdGFuoi/431h3NyTE
         TVec3q8xxIqQEWaIbaMegtwhZHFi33eGI77rGZIH/Q6jZBXeeB741yqsSTDGXvxMu4m1
         GQH0sBgkSwmY3hnfaumzFuMtVp24pEHblE7qz6nTZXDU35NDBDwma8OAMnfYfSynCRzt
         R1pVv7fYYztShucy6UoAf3X+wS4UVtg34dnh83myC9OL7VmkWHJDHx17MWVyIBWLjePL
         TJFlWUz4s8QVgkVXKw4UjzINc4GR4FAVtZayUeCU37IBx7+JX231UpvX1QY0z82PTzeP
         UeRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=m0vRc1sId1C2WIrhVfMM1dqLPpNNRKy6Bf2LlVl4icg=;
        b=PQbD2L+hKpe+4z5BpbrrYeMISc/gINwZwWy2+D/9tFWjAgYKJS0kGMtSQ9ZrkBrs5L
         4ohVUGV9066sd9rSPLsVnB1PSdT4+mRfTaOpl0qakYWJer0tfipEE8viY2E2qOqQW1vv
         +yTQhM99K0hpoE4P81ke01LJyabChI0YVlbCxTufzgLPBRfK+FVH5LtzmtuC0VasGls/
         Weo7mgwv45GRO5IrcPBHMs3gII0EM/Wi7A1UlpfVDTVw5By/XRQ5ufBPybUdpUD/LRrI
         xLkjYbV6F5ZG81gF6hJkKqG1VzTsWoZXS8di0F+IZzLICBFaC2oYrjURFWWC3F+EmKhU
         A7iQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVSprsZStLHhMFO2G0EFRc/bVYuiRE9gr/7l2BceiCyHUG8o/jW
	+NezcF7z8wEwvJDVcl3MIQc=
X-Google-Smtp-Source: APXvYqx84wvGdb+72VAhRVGNHUpca564UQzebrlMdMNU/WmDsJjjBBXXuYqvjkSl4OiK9TIrd42FZw==
X-Received: by 2002:a2e:300d:: with SMTP id w13mr9785452ljw.117.1574374942814;
        Thu, 21 Nov 2019 14:22:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8ed1:: with SMTP id e17ls1232557ljl.2.gmail; Thu, 21 Nov
 2019 14:22:22 -0800 (PST)
X-Received: by 2002:a2e:9d97:: with SMTP id c23mr9552396ljj.121.1574374942105;
        Thu, 21 Nov 2019 14:22:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574374942; cv=none;
        d=google.com; s=arc-20160816;
        b=BCyCE4cLA1bV37eiVN9J7F1lVePRjoaJL2R41nSsAUP6A3xhDyqnJzq6M8teAeDIZ3
         UVashWeqUNhDSTH8Lg7NP4/uWnKOg6QGVRHjssL9s35CvmwjsAH8NlREHjEEGmur6mqZ
         HC5jnWKy4zm3O4BZGYhyA5Hwj85PQtGITNQIanctOEex+0vsu72Bo2YC6JuDBWMEWXpQ
         IYGfAqN8vbf9xz+ZdMMRAI17yFuUvUCogzSN5DeoBGYIZZz/LKyVXq0uB+ipUJVafII3
         s8tegb9KXW0kFmB6iAT/79ae7SvLWpfhCCvpqxnMeLA7NvvL13eLGhDc/yXoQv3uguJ6
         RTTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=ji3gnkCDRPtNWFKJJcjkuQMsuapO/ZRLFz7EqSXe6e0=;
        b=B82a0ugZmbqvco+obbtzSr4MlkZyGAej9jC/9l4UNgoa4f0wsGe/eCbfJXl9Kdf0OY
         5bwwNS63yXSmVLauInXHXkt8r4bzq3bwL1CxKUG6fuP0bRNUdObox28sTtqgh5HQ8gYl
         xHpbAnGb5YAw1wsDAYDMiaVAJhuH7zbzGHsHDnka+lxz75+py6cSBItY0cMFzogIB65s
         vsLSbdTYVQInmzjQIiZRl4SM7dQzdkbTujRPeK1Cs8gMyoUg5vPyt77VzQ3G32M5z+WV
         IL4wiuUOUu/G4pLbPSSxMzVJCjA098aacuLyDhccVtAvLUGTIJW0ayzs4pdTl8fGIxme
         ORlg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id b13si252387ljk.4.2019.11.21.14.22.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 21 Nov 2019 14:22:22 -0800 (PST)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [192.168.15.154]
	by relay.sw.ru with esmtp (Exim 4.92.3)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1iXuq2-0007vl-St; Fri, 22 Nov 2019 01:22:11 +0300
Subject: Re: [PATCH v4 1/2] kasan: detect negative size in memory operation
 function
To: Walter Wu <walter-zh.wu@mediatek.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Matthias Brugger <matthias.bgg@gmail.com>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
 wsd_upstream <wsd_upstream@mediatek.com>,
 linux-mediatek@lists.infradead.org, Andrew Morton <akpm@linux-foundation.org>
References: <20191112065302.7015-1-walter-zh.wu@mediatek.com>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <b2ba5228-dec0-9acf-49e9-d57f156814ef@virtuozzo.com>
Date: Fri, 22 Nov 2019 01:20:23 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.2
MIME-Version: 1.0
In-Reply-To: <20191112065302.7015-1-walter-zh.wu@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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



On 11/12/19 9:53 AM, Walter Wu wrote:
> KASAN missed detecting size is a negative number in memset(), memcpy(),
> and memmove(), it will cause out-of-bounds bug. So needs to be detected
> by KASAN.
> 
> If size is a negative number, then it has a reason to be defined as
> out-of-bounds bug type.
> Casting negative numbers to size_t would indeed turn up as
> a large size_t and its value will be larger than ULONG_MAX/2,
> so that this can qualify as out-of-bounds.
> 
> KASAN report is shown below:
> 
>  BUG: KASAN: out-of-bounds in kmalloc_memmove_invalid_size+0x70/0xa0
>  Read of size 18446744073709551608 at addr ffffff8069660904 by task cat/72
> 
>  CPU: 2 PID: 72 Comm: cat Not tainted 5.4.0-rc1-next-20191004ajb-00001-gdb8af2f372b2-dirty #1
>  Hardware name: linux,dummy-virt (DT)
>  Call trace:
>   dump_backtrace+0x0/0x288
>   show_stack+0x14/0x20
>   dump_stack+0x10c/0x164
>   print_address_description.isra.9+0x68/0x378
>   __kasan_report+0x164/0x1a0
>   kasan_report+0xc/0x18
>   check_memory_region+0x174/0x1d0
>   memmove+0x34/0x88
>   kmalloc_memmove_invalid_size+0x70/0xa0
> 
> [1] https://bugzilla.kernel.org/show_bug.cgi?id=199341
> 
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> Reported-by: Dmitry Vyukov <dvyukov@google.com>
> Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Reported-by: kernel test robot <lkp@intel.com>
> ---

Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b2ba5228-dec0-9acf-49e9-d57f156814ef%40virtuozzo.com.
