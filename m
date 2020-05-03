Return-Path: <kasan-dev+bncBAABB4FQXL2QKGQEVQAG5XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id E08E61C2B25
	for <lists+kasan-dev@lfdr.de>; Sun,  3 May 2020 12:09:53 +0200 (CEST)
Received: by mail-ua1-x937.google.com with SMTP id c24sf6208357uao.10
        for <lists+kasan-dev@lfdr.de>; Sun, 03 May 2020 03:09:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588500592; cv=pass;
        d=google.com; s=arc-20160816;
        b=YzkJEukGI1WzPThSEc1nqbEhoGkgkYPbVgfzeih9pZ6GdaZOk7klID6uU0kXk5sK9a
         w8EWH5jO+6Xty2f4DQuEnnfu9/hQcLYxqO2Czb9SL3noJhUQmzcUZvuCtns/hjlqPdBz
         p25cX5j1Jov7BnoK3GfIHGqlua1efA8Zn2T2PPGEeIp90JERz9gCaGL63PGC8KtPKitQ
         jNXDF7INKMPbOyBM4HI5qy9K4sJte+MkkMnRxFcZcY3JBstRYVTDjtsCI3fgAzErRDHp
         s++ebnqZvhARWv/DHWSORIseHikSo7iIulWF5ZdFP80k9n4wbjY0NeSXXQ20XZnH14oF
         9uFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :message-id:in-reply-to:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=S7ULsD9amN3TcoCu7pgIupv7Zn0rU1EM7G/3+fj/EuU=;
        b=lXX89gnPFUMEOyZ0Rf+5TnZYQPz4cfftxiqeQJKqKV2IW3Zbokq7N50xgQ8Yxq3Sl4
         R8xJ4ONuv38abJV4INOKhSYcgLKtPnA2wl8m2j9mRRopjOKSa5QxXIuEJ0CoUgCPI7BU
         5JBgtl2xLBHDGVJR7hZbSIBJkWcWJ5LzHagea2dxHOrG+/amy9kFm+6lCbG8riKHVUkA
         pKiYMwQM8PpsEQwZ7UFlk/igS3WEBGTTsbJ4iGqvP974tlXf/YjDLlWSzDYoZeo+S7Ts
         cX1iCgbaLBQwu1p6wT7Jh4/rfat4XWtyjaokxbRcvIPjvODja3MGN+DfP4djthTVpqBN
         0BjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=pLQkLJM5;
       spf=pass (google.com: domain of alan.maguire@oracle.com designates 156.151.31.86 as permitted sender) smtp.mailfrom=alan.maguire@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:in-reply-to:message-id:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=S7ULsD9amN3TcoCu7pgIupv7Zn0rU1EM7G/3+fj/EuU=;
        b=UnLgqvy70H6WkNTggqeUFPCGXThLVRdMEDigpv1P0Dkpy0qVr6topg/hvXE0zjC0Zc
         IeQgwxaHvWu2nLOOcwBDdwub3G+6V6P+g2bhN8T+2UrI01sPrz3YLB9oWE7p1RFFtazl
         VT5LT1wZN2a9HWE65aUJKDMGod8C5aUm6zI0ZKhvyCFe9kwARbeHEVkEEFLI4XMRwpfC
         F0QDLh72nnIBOVaiastFsfTDcQXE4D8wTCCk2RBT0pr5yF1JJOKZaxX/INTJl42kVQT9
         e6Zd/BIMX2cbDx2K0BI4Y03nCJYRttnJakZrhN48M9lT7gF2AU158i1TcWa+34a0VanH
         vZmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:in-reply-to
         :message-id:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S7ULsD9amN3TcoCu7pgIupv7Zn0rU1EM7G/3+fj/EuU=;
        b=Tc4mJrksnUQylTmPHUfTw5Xn4qBcaNGqAZkQbpskPBKY2jZrkFCkrS2LDK4I3Ahz/h
         y2OVEiiFhS6aAcFLJe9comZiU0/HEmeQpMOX50XjgrLZ7SLeHdV73F8H1VI6+m2Xw889
         Amii8ZOfPUj48HN8Z+6Vz3YBvSzSIkyrxNTW/+62gLV+Pwk86+UHLE5fNMw14OLphgt5
         o8gBTghpQwEyBbfk232mNNii+EFwWms7HyYcyq3t56vlMTT6Ful3jGE10nugveyVKo6C
         wuQj9z6iagwdL1LKwZaHdOwZpnCf3u5aQwY1V5nrXhRK9DVlLa5BVpKmdg0sUDImjn4d
         NmJQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYixmdtlFYneJ7bTZcsufYR/vkeu3lyMIB6NACr/q0x6RGDkefb
	2lIT1hORnXzyu2UPIIYWdvs=
X-Google-Smtp-Source: APiQypJktsBjlSOSInYc/CEykwO5NZhzT7NnqYBnIz12ZMzDqOqyerHxTZJOT9avu9Nx1+MgfRbTmw==
X-Received: by 2002:a67:ffcf:: with SMTP id w15mr8402758vsq.213.1588500592552;
        Sun, 03 May 2020 03:09:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c319:: with SMTP id r25ls1424348vsj.4.gmail; Sun, 03 May
 2020 03:09:52 -0700 (PDT)
X-Received: by 2002:a67:2e45:: with SMTP id u66mr8428471vsu.178.1588500592183;
        Sun, 03 May 2020 03:09:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588500592; cv=none;
        d=google.com; s=arc-20160816;
        b=WFLLyvv4yW839MdyB2imlfmSoSpAkSDI7jkM3BUmbW+dAmzf4zKxfcRyWNJxW2NVRz
         KIQdSpyWdk/ytuE5t6AKN8xPzww3nFRA2jGrMYXoy/Lxn/l9rH3ZoNKsr0YrPuHtHdFf
         5SLDO0Bx+8Mztwf/mchEmd6d8SNMD71Y7xYjWhE10ZySOj7CyKyY1AtUK/6w599G8ahQ
         wM/5wuQAFyEx+8A/u/VpBeDefvsphOU86pHejmlUWmhaGe6yhvCVwowx4bCecPuzIcMP
         9aPFkje9PeiT8eXK3ouEv2rmO/bsRKhjaSs4MRXgaBYC4O4TAbwehIhrBGlaw/UGzxmo
         Kvyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:references:message-id:in-reply-to:subject
         :cc:to:from:date:dkim-signature;
        bh=+3cvJANHAAeU4d22dlyULTuCEPl9tYfeqegQxmVM3JU=;
        b=DbSK0s4f/F5+ZA1BtB6hrUiHcFEFNiS9IFu4tHQgIgYC64JMLpSrUGqs5T0WKKSpRk
         5NdTUqk26rsL2F0gjkN262i7Jy9xyOzqh//ydKSS0+DlKEA4O6h8I1tJNpmRsB6Vf66C
         f2P3r7rWvWK4ljJWwvNSv1QI9uDsRB9Q0dK9341E4OYh77iURUCfkyFt/j+GJz2u/CkV
         8u+hr/evUKoim6OOJDGXw9of+GoQs/izX5mzWD4Xjola07w8w+mhwBhjUIcZh84NdEtt
         PnDvQuj/gFajFKTwXUPY4lKnFRVCdYYObOUfohOcDu4f4r4OpTTZhk844La+54uKsEgk
         Pp9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=pLQkLJM5;
       spf=pass (google.com: domain of alan.maguire@oracle.com designates 156.151.31.86 as permitted sender) smtp.mailfrom=alan.maguire@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from userp2130.oracle.com (userp2130.oracle.com. [156.151.31.86])
        by gmr-mx.google.com with ESMTPS id l3si652040uap.0.2020.05.03.03.09.51
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 03 May 2020 03:09:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of alan.maguire@oracle.com designates 156.151.31.86 as permitted sender) client-ip=156.151.31.86;
Received: from pps.filterd (userp2130.oracle.com [127.0.0.1])
	by userp2130.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 043A3XbN179569;
	Sun, 3 May 2020 10:09:48 GMT
Received: from userp3030.oracle.com (userp3030.oracle.com [156.151.31.80])
	by userp2130.oracle.com with ESMTP id 30s09qu5e0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Sun, 03 May 2020 10:09:47 +0000
Received: from pps.filterd (userp3030.oracle.com [127.0.0.1])
	by userp3030.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 043A7XNR129168;
	Sun, 3 May 2020 10:09:47 GMT
Received: from aserv0121.oracle.com (aserv0121.oracle.com [141.146.126.235])
	by userp3030.oracle.com with ESMTP id 30sjbane2a-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Sun, 03 May 2020 10:09:47 +0000
Received: from abhmp0001.oracle.com (abhmp0001.oracle.com [141.146.116.7])
	by aserv0121.oracle.com (8.14.4/8.13.8) with ESMTP id 043A9d6c015487;
	Sun, 3 May 2020 10:09:45 GMT
Received: from dhcp-10-175-179-100.vpn.oracle.com (/10.175.179.100)
	by default (Oracle Beehive Gateway v4.0)
	with ESMTP ; Sun, 03 May 2020 10:09:38 +0000
Date: Sun, 3 May 2020 11:09:30 +0100 (BST)
From: Alan Maguire <alan.maguire@oracle.com>
X-X-Sender: alan@localhost
To: David Gow <davidgow@google.com>
cc: trishalfonso@google.com, brendanhiggins@google.com,
        aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com,
        peterz@infradead.org, juri.lelli@redhat.com,
        vincent.guittot@linaro.org, linux-kernel@vger.kernel.org,
        kasan-dev@googlegroups.com, kunit-dev@googlegroups.com,
        linux-kselftest@vger.kernel.org
Subject: Re: [PATCH v7 0/5] KUnit-KASAN Integration
In-Reply-To: <20200424061342.212535-1-davidgow@google.com>
Message-ID: <alpine.LRH.2.21.2005031101130.20090@localhost>
References: <20200424061342.212535-1-davidgow@google.com>
User-Agent: Alpine 2.21 (LRH 202 2017-01-01)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9609 signatures=668687
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxscore=0 bulkscore=0 phishscore=0
 malwarescore=0 adultscore=0 spamscore=0 mlxlogscore=999 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2003020000
 definitions=main-2005030091
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9609 signatures=668687
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 bulkscore=0 mlxscore=0
 lowpriorityscore=0 spamscore=0 adultscore=0 clxscore=1011 suspectscore=0
 priorityscore=1501 malwarescore=0 mlxlogscore=999 phishscore=0
 impostorscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2003020000 definitions=main-2005030090
X-Original-Sender: alan.maguire@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2020-01-29 header.b=pLQkLJM5;
       spf=pass (google.com: domain of alan.maguire@oracle.com designates
 156.151.31.86 as permitted sender) smtp.mailfrom=alan.maguire@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
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

On Thu, 23 Apr 2020, David Gow wrote:

> This patchset contains everything needed to integrate KASAN and KUnit.
> 
> KUnit will be able to:
> (1) Fail tests when an unexpected KASAN error occurs
> (2) Pass tests when an expected KASAN error occurs
> 
> Convert KASAN tests to KUnit with the exception of copy_user_test
> because KUnit is unable to test those.
> 
> Add documentation on how to run the KASAN tests with KUnit and what to
> expect when running these tests.
> 
> This patchset depends on:
> - "[PATCH v3 kunit-next 0/2] kunit: extend kunit resources API" [1]
> - "[PATCH v3 0/3] Fix some incompatibilites between KASAN and
>   FORTIFY_SOURCE" [2]
> 
> Changes from v6:
>  - Rebased on top of kselftest/kunit
>  - Rebased on top of Daniel Axtens' fix for FORTIFY_SOURCE
>    incompatibilites [2]
>  - Removed a redundant report_enabled() check.
>  - Fixed some places with out of date Kconfig names in the
>    documentation.
>

Sorry for the delay in getting to this; I retested the
series with the above patchsets pre-applied; all looks
good now, thanks!  Looks like Daniel's patchset has a v4
so I'm not sure if that will have implications for applying
your changes on top of it (haven't tested it yet myself).

For the series feel free to add

Tested-by: Alan Maguire <alan.maguire@oracle.com>

I'll try and take some time to review v7 shortly, but I wanted
to confirm the issues I saw went away first in case you're
blocked.  The only remaining issue I see is that we'd need the
named resource patchset to land first; it would be good
to ensure the API it provides is solid so you won't need to
respin.

Thanks!

Alan
 
> Changes from v5:
>  - Split out the panic_on_warn changes to a separate patch.
>  - Fix documentation to fewer to the new Kconfig names.
>  - Fix some changes which were in the wrong patch.
>  - Rebase on top of kselftest/kunit (currently identical to 5.7-rc1)
> 
> Changes from v4:
>  - KASAN no longer will panic on errors if both panic_on_warn and
>    kasan_multishot are enabled.
>  - As a result, the KASAN tests will no-longer disable panic_on_warn.
>  - This also means panic_on_warn no-longer needs to be exported.
>  - The use of temporary "kasan_data" variables has been cleaned up
>    somewhat.
>  - A potential refcount/resource leak should multiple KASAN errors
>    appear during an assertion was fixed.
>  - Some wording changes to the KASAN test Kconfig entries.
> 
> Changes from v3:
>  - KUNIT_SET_KASAN_DATA and KUNIT_DO_EXPECT_KASAN_FAIL have been
>  combined and included in KUNIT_DO_EXPECT_KASAN_FAIL() instead.
>  - Reordered logic in kasan_update_kunit_status() in report.c to be
>  easier to read.
>  - Added comment to not use the name "kasan_data" for any kunit tests
>  outside of KUNIT_EXPECT_KASAN_FAIL().
> 
> Changes since v2:
>  - Due to Alan's changes in [1], KUnit can be built as a module.
>  - The name of the tests that could not be run with KUnit has been
>  changed to be more generic: test_kasan_module.
>  - Documentation on how to run the new KASAN tests and what to expect
>  when running them has been added.
>  - Some variables and functions are now static.
>  - Now save/restore panic_on_warn in a similar way to kasan_multi_shot
>  and renamed the init/exit functions to be more generic to accommodate.
>  - Due to [3] in kasan_strings, kasan_memchr, and
>  kasan_memcmp will fail if CONFIG_AMD_MEM_ENCRYPT is enabled so return
>  early and print message explaining this circumstance.
>  - Changed preprocessor checks to C checks where applicable.
> 
> Changes since v1:
>  - Make use of Alan Maguire's suggestion to use his patch that allows
>    static resources for integration instead of adding a new attribute to
>    the kunit struct
>  - All KUNIT_EXPECT_KASAN_FAIL statements are local to each test
>  - The definition of KUNIT_EXPECT_KASAN_FAIL is local to the
>    test_kasan.c file since it seems this is the only place this will
>    be used.
>  - Integration relies on KUnit being builtin
>  - copy_user_test has been separated into its own file since KUnit
>    is unable to test these. This can be run as a module just as before,
>    using CONFIG_TEST_KASAN_USER
>  - The addition to the current task has been separated into its own
>    patch as this is a significant enough change to be on its own.
> 
> 
> [1] https://lore.kernel.org/linux-kselftest/1585313122-26441-1-git-send-email-alan.maguire@oracle.com/T/#t
> [2] https://lkml.org/lkml/2020/4/23/708
> [3] https://bugzilla.kernel.org/show_bug.cgi?id=206337
> 
> 
> 
> David Gow (1):
>   mm: kasan: Do not panic if both panic_on_warn and kasan_multishot set
> 
> Patricia Alfonso (4):
>   Add KUnit Struct to Current Task
>   KUnit: KASAN Integration
>   KASAN: Port KASAN Tests to KUnit
>   KASAN: Testing Documentation
> 
>  Documentation/dev-tools/kasan.rst |  70 +++
>  include/kunit/test.h              |   5 +
>  include/linux/kasan.h             |   6 +
>  include/linux/sched.h             |   4 +
>  lib/Kconfig.kasan                 |  18 +-
>  lib/Makefile                      |   3 +-
>  lib/kunit/test.c                  |  13 +-
>  lib/test_kasan.c                  | 688 +++++++++++++-----------------
>  lib/test_kasan_module.c           |  76 ++++
>  mm/kasan/report.c                 |  34 +-
>  10 files changed, 514 insertions(+), 403 deletions(-)
>  create mode 100644 lib/test_kasan_module.c
> 
> -- 
> 2.26.2.303.gf8c07b1a785-goog
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/alpine.LRH.2.21.2005031101130.20090%40localhost.
