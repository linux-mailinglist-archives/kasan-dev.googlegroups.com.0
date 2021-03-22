Return-Path: <kasan-dev+bncBC33FCGW2EDRBOER4SBAMGQEQQPXEUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id CEF3134519D
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Mar 2021 22:14:32 +0100 (CET)
Received: by mail-ej1-x640.google.com with SMTP id li22sf28020ejb.18
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Mar 2021 14:14:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616447672; cv=pass;
        d=google.com; s=arc-20160816;
        b=VvfK1CnMbDa+IS3FDFB7mApQxTTZxPAzAE8WywH8O6t8SVpfEd651cEC3qt+jSZ39g
         H5/0L8rKU2H5APN39t/Fxv2AftGXGed6bzgKVTGl2pfKBBKQGILoE/c7Lzj2elZZjt8T
         3aU3qp2eOHRVcQQZCBbixjO8S8JtRlQb1mcJNbtq2oJUIzAnK2/4AN2KkU0pfsxzxS3m
         8fAVz7fs+ugk4VvDZ3X5daiKPHzo1hZQlP1X9yDkCYc7NaoGD+ZqxbuirOEiDKsjGm6V
         IkWetEmB1R0bNGPlNV0WhbGzSDRxGoDUDn15xErE/vHqkf50ihVibIy7TsAKxPHfy6U6
         K4Tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=EGUYDk6e5ZwIdwxmBaiUVBmSD9BYqJAqozPzfWLXsDU=;
        b=WFsTFKmKfTeHWIf+1HtXb9byQ8XTFkf3Q3f8yklxDrBZY41Xl4HeYqxLi7Xpm4q4l+
         Nvv7fJrh+PQC8CHtGynCwlHAFy2vgPThUD6ErzjJxO84V+nBDyKxJqzIZ/zcm9voYR6T
         /akFZbN61ggfAC6VgNJHtvetuceeWoHwyYgDRAVQmLaoQ2wvzmyHfVLcS/4yWKzy/bqy
         sSCpMphm6EJeoeFqkpzpvQ1VC/scOnvbxyHE/r5I0E8Fe3/p+9PjIUpFPdjj/A5PykH3
         1Sdyo40xtNq9KP+l48ex8QQVXGTMIq1PW3nvmN+t4RR0NSl5Af7y9Eg7BLRsQfYPiaxw
         /LhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alexander-lochmann.de header.s=key2 header.b=i614trfF;
       spf=pass (google.com: domain of info@alexander-lochmann.de designates 188.68.63.98 as permitted sender) smtp.mailfrom=info@alexander-lochmann.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EGUYDk6e5ZwIdwxmBaiUVBmSD9BYqJAqozPzfWLXsDU=;
        b=SF27XFUcQGBqsvSN2yeCSi0Sb4IOjBN+S9MtX0dNT7s5Ru/zDdhFJIeNWzmDl9gUt/
         gd0tLcxZjhWQe9xIoujQSDnYCp8CuBVsgiFl4cf7lMzSDsS5Q3VacORUvmTWl6TwA7+Z
         HUAHljx9zDIOhsG+TviRpqS/TKCGFAZy3DS/XvKRSkAbtd9ImE/b8F16K08sd8EB12fj
         Szl4zUfDHsjQ6UC2tFl3xzVUFjhUdP6gdO0wAXD9e/ncvpBmwhQo6YudT63caRSgUAGc
         FQSQ90JmqCdEHgMPFs3Z5mnr0rL7PFHkq2zS5hXl6Yibg7NmsmeADmu2aQIiU+HZOc4X
         We2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=EGUYDk6e5ZwIdwxmBaiUVBmSD9BYqJAqozPzfWLXsDU=;
        b=DoDV1lnmyJt3930b1RcWLyS7cc7Rip5qCsFdv6hmQ/5D27bNMmZNn3L0Hr34YQqbw0
         xImTAz02YXDmw6cPV1jZjD/ksMRbYZsmVkijbiifs9+igl0ULpYgEtI5lkpoKvlBL3M8
         az4rd7AmYaATbcFkBrYo/Gs4KlAtEyrzKrGn2MW3Lo71++GoHBGDt/SHKL58xChL9ZkO
         GhCDWqab5IU+LNKMfMF5D1GlXhLXdHVVBYuMxfp+LNKOIlbuDQMOQkD1cw/cyVri5/dz
         keeUe3GI7iFe9H3ZyxQMZXHgPGMdq+M0VO/X3B+OYvf3f0W0TtP8A1Fe2A3fa/bZ6R76
         aToQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533lghC0XZxgG7eEd/r068eKyeFepk1FCWWMaYNmB814GUjK5+IG
	+aEemWUBT5kqaMlEnr8FL3g=
X-Google-Smtp-Source: ABdhPJzjQcLBtsbcycWF+vNl+vGxrx86St0jMKFKTIjwAtJwnvAEWJcgq9wYFz0TxpLqdoL8KqIFlw==
X-Received: by 2002:a17:906:f0d0:: with SMTP id dk16mr1751117ejb.48.1616447672618;
        Mon, 22 Mar 2021 14:14:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c653:: with SMTP id z19ls3115942edr.2.gmail; Mon, 22 Mar
 2021 14:14:31 -0700 (PDT)
X-Received: by 2002:a05:6402:646:: with SMTP id u6mr1582006edx.250.1616447671725;
        Mon, 22 Mar 2021 14:14:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616447671; cv=none;
        d=google.com; s=arc-20160816;
        b=sP4vJPRbCLAVNSi6Km/YXB0RnACMxqOuYzOsyOMHCgHQVxIbcxcUHH5rDjnuAC5/72
         8Rt2g0NFZG1ix4BeG0Tk7HIlucZoDm38IqftyLy5jaX68SI3E8O0620yXXsuKWI7ThSI
         fIt7TBWUxApgZhIYQ6SXNgQjiykFcBWtY84vpc3qMeRiel+saxXLe6gZ2igHSHkZFUiK
         57YP1GCnhQyf35SCwNxYc+xd4nSBc8lyOsGPR768y8GufQj/6cKFWf5VrjvE+0zF+oAu
         10k2E8tgqw75gLLYO9yfJuBVrEZqSXsbk57elKcaj3yAHQtFdwK7I9qlyOdTkvdaIPYT
         0hEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=+KrRzh5xmraTlZE7Njs3hlaa7m+E5z8AfQskFmxJcRw=;
        b=oudJaShFRaT+L8H5QXV41Lr/Vv3yfnurMRhyEj0QSkHFiyii94pb9vTnjGKHZbXTss
         upsnxAJYC0tdTuuxgT2B2yTP5Pk/n3MN6rJGgQ6ws+aczi9+BoZ+xw+XpymPMAgqb+z1
         4TMEHwhsomDrMkukHxM4Vvd0FKN6MOW7bBHZLYjMWBtomNyHPG8p7cDn37N+NtpVbIvM
         mxxfbCk+vfw+e0p1oq1G/A6SbfZM3G2kHXunFmHdA6o0ejDPsqay0Zcr2pj2Nda8FaG6
         XTZ21ttiZ0gvqnqUZvKCSiReIoknLDLAGbahDEoggKyCDNM9eGlsLpTnY9hwtm+l+/qM
         Wvew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alexander-lochmann.de header.s=key2 header.b=i614trfF;
       spf=pass (google.com: domain of info@alexander-lochmann.de designates 188.68.63.98 as permitted sender) smtp.mailfrom=info@alexander-lochmann.de
Received: from relay.yourmailgateway.de (relay.yourmailgateway.de. [188.68.63.98])
        by gmr-mx.google.com with ESMTPS id sd27si437255ejb.1.2021.03.22.14.14.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 22 Mar 2021 14:14:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of info@alexander-lochmann.de designates 188.68.63.98 as permitted sender) client-ip=188.68.63.98;
Received: from mors-relay-2501.netcup.net (localhost [127.0.0.1])
	by mors-relay-2501.netcup.net (Postfix) with ESMTPS id 4F46h71Xhqz6QSW;
	Mon, 22 Mar 2021 22:14:31 +0100 (CET)
Received: from policy01-mors.netcup.net (unknown [46.38.225.35])
	by mors-relay-2501.netcup.net (Postfix) with ESMTPS id 4F46h7166Xz5DJR;
	Mon, 22 Mar 2021 22:14:31 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at policy01-mors.netcup.net
X-Spam-Flag: NO
X-Spam-Score: -2.9
X-Spam-Level: 
X-Spam-Status: No, score=-2.9 required=6.31 tests=[ALL_TRUSTED=-1,
	BAYES_00=-1.9, SPF_PASS=-0.001, URIBL_BLOCKED=0.001]
	autolearn=ham autolearn_force=no
Received: from mx2e12.netcup.net (unknown [10.243.12.53])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by policy01-mors.netcup.net (Postfix) with ESMTPS id 4F46h441jQz8tGR;
	Mon, 22 Mar 2021 22:14:28 +0100 (CET)
Received: from [IPv6:2003:ed:7f03:8df0:3b15:ded:17a1:3116] (p200300ed7f038df03b150ded17a13116.dip0.t-ipconnect.de [IPv6:2003:ed:7f03:8df0:3b15:ded:17a1:3116])
	by mx2e12.netcup.net (Postfix) with ESMTPSA id 2364CA1AFC;
	Mon, 22 Mar 2021 22:14:27 +0100 (CET)
Received-SPF: pass (mx2e12: connection is authenticated)
Subject: Re: [PATCH] Introduced new tracing mode KCOV_MODE_UNIQUE.
To: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
 Andrey Konovalov <andreyknvl@google.com>, Jonathan Corbet <corbet@lwn.net>,
 Miguel Ojeda <ojeda@kernel.org>, Randy Dunlap <rdunlap@infradead.org>,
 Andrew Klychkov <andrew.a.klychkov@gmail.com>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Andrew Morton <akpm@linux-foundation.org>,
 Aleksandr Nogikh <nogikh@google.com>, Jakub Kicinski <kuba@kernel.org>,
 Wei Yongjun <weiyongjun1@huawei.com>,
 Maciej Grochowski <maciej.grochowski@pm.me>,
 kasan-dev <kasan-dev@googlegroups.com>,
 Linux Doc Mailing List <linux-doc@vger.kernel.org>,
 linux-kernel <linux-kernel@vger.kernel.org>
References: <CACT4Y+bdXrFoL1Z_h5s+5YzPZiazkyr2koNvfw9xNYEM69TSvg@mail.gmail.com>
 <20210321184403.8833-1-info@alexander-lochmann.de>
 <CANiq72n+hqW5i4Cj8jS9oHYTcjQkoAZkw6OwhZ0vhkS=mayz_g@mail.gmail.com>
From: Alexander Lochmann <info@alexander-lochmann.de>
Message-ID: <09e2b5a1-16ad-037a-88d2-6b29bc3fea6a@alexander-lochmann.de>
Date: Mon, 22 Mar 2021 22:14:26 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <CANiq72n+hqW5i4Cj8jS9oHYTcjQkoAZkw6OwhZ0vhkS=mayz_g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: de-DE
X-PPP-Message-ID: <161644766760.12995.11637851970269855327@mx2e12.netcup.net>
X-PPP-Vhost: alexander-lochmann.de
X-NC-CID: kW0vvfUiLZdNgXacqVw4qIspfyEOcREZsez+ffHhqAayMnL2gBkxpC7V
X-Original-Sender: info@alexander-lochmann.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alexander-lochmann.de header.s=key2 header.b=i614trfF;
       spf=pass (google.com: domain of info@alexander-lochmann.de designates
 188.68.63.98 as permitted sender) smtp.mailfrom=info@alexander-lochmann.de
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



On 22.03.21 13:17, Miguel Ojeda wrote:
> Hi Alexander,
> 
> On Sun, Mar 21, 2021 at 8:14 PM Alexander Lochmann
> <info@alexander-lochmann.de> wrote:
>>
>> diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
>> index d2c4c27e1702..e105ffe6b6e3 100644
>> --- a/Documentation/dev-tools/kcov.rst
>> +++ b/Documentation/dev-tools/kcov.rst
>> @@ -127,6 +127,86 @@ That is, a parent process opens /sys/kernel/debug/kcov, enables trace mode,
>>  mmaps coverage buffer and then forks child processes in a loop. Child processes
>>  only need to enable coverage (disable happens automatically on thread end).
>>
>> +If someone is interested in a set of executed PCs, and does not care about
>> +execution order, he or she can advise KCOV to do so:
> 
> Please mention explicitly that KCOV_INIT_UNIQUE should be used for
> that, i.e. readers of the example shouldn't need to read every line to
> figure it out.
> 
>> +    #define KCOV_INIT_TRACE                    _IOR('c', 1, unsigned long)
> 
> Trace is not used in the example.
> 
>> +       /* KCOV was initialized, but recording of unique PCs hasn't been chosen yet. */
>> +       KCOV_MODE_INIT_UNQIUE = 2,
> 
> Typo? It isn't used?
It is a typo. It should be used...
> 
> PS: not sure why I was Cc'd, but I hope that helps.
Thx for your feedback. get_maintainer.pl told me to include you in Cc.

Cheers,
Alex
> 
> Cheers,
> Miguel
> 

-- 
Alexander Lochmann                PGP key: 0xBC3EF6FD
Heiliger Weg 72                   phone:  +49.231.28053964
D-44141 Dortmund                  mobile: +49.151.15738323

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/09e2b5a1-16ad-037a-88d2-6b29bc3fea6a%40alexander-lochmann.de.
