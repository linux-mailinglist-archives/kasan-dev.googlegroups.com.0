Return-Path: <kasan-dev+bncBC33FCGW2EDRB74UTGFAMGQEXYEAX7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 76D15410887
	for <lists+kasan-dev@lfdr.de>; Sat, 18 Sep 2021 22:22:24 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id h15-20020aa7de0f000000b003d02f9592d6sf12158390edv.17
        for <lists+kasan-dev@lfdr.de>; Sat, 18 Sep 2021 13:22:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631996544; cv=pass;
        d=google.com; s=arc-20160816;
        b=PN8IwOmMIeHCKOWvAfpfjGN4SDlqAsRJkBMfwvD/2BMziniWn/PLzXQwa1+7nWVlbw
         ZW//h/Gvzy4zAk1/d6O/i16mhALfeZVxQt8LC3Y1S/Jj+AowDHVbImZYk3vTxpHYck8y
         njB4FKpZdWx19zkRXRbqSO5UGAEyj+inoxYpzCxvI/UfhFpZs0JgT7p91A1IAlx4qBaU
         fM25TynzaORyZ2zw12B8GB67mYCIrRxN8Y3DKIAjbpD9ly6gW+U6MalKDbTPAeakw+vR
         5zMkWcvMYbGOphRflcgd4W0Xvd+DqcQkPq5hbU9egjsIyMhdt6S9JtzZCij/ZxEYAO9U
         EtyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:mime-version:user-agent
         :date:message-id:subject:from:references:cc:to:sender:dkim-signature;
        bh=IWpvnK8/ZB7HsPaYnO4waIX/XExFp9sISfvHE+I99Vc=;
        b=c0rkS6UuGXDLKiXnXXG1+kZCJFf4JKkdFTOM3ZiCr87q3xUzzQWpjTsQ3RwcqrHOU0
         NLGB5ClIEbFoHDENG7VgeruAUEXPKT8DWB1RDuvqAdZxBt2FFGKN8/og7t9phcpO1Xpe
         zjY1UO0ecPoy08NdhJ9udicTCMga4eolNNjQwG8cEr74kfAeN1UhDsuuKHuSQqPegcRt
         f7uY2O1vxIKsh8Gbfn2PoyGvttzaaXPO7MgGPuta89d439xHbrzAcaVVLeY42ToCP+QZ
         aYiID6m6CiuEcdJ1D+RUZ24yTsq7NYd98oUOF4Yypkh3b9dawVzEZvdFOJDK/pZThbxZ
         XEMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alexander-lochmann.de header.s=key2 header.b=khznvf5Y;
       spf=pass (google.com: domain of info@alexander-lochmann.de designates 185.244.192.111 as permitted sender) smtp.mailfrom=info@alexander-lochmann.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:to:cc:references:from:subject:message-id:date:user-agent
         :mime-version:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IWpvnK8/ZB7HsPaYnO4waIX/XExFp9sISfvHE+I99Vc=;
        b=dQBAjv9nMI3X2Fq9l2u2934PyW4ThXRTyTFoaaCZckuUJFqb7Q9ckwuMdLEgamoWpg
         KyMnIR/2+9RsfJHgu2hDB2buzaYnmRYNLFKJ0em/bNoaC37zM4CcHea2YzWcWnxHk+LF
         oA4Y3nP+FQl/LGviFY+uyaLcsgcBwMsDw0Ns0lmDcuhzofT4Hh2PnQimdhnUhsCHPsg4
         JAvr40p0PCdE1eEIf7eu2mKYAQMnoWtuqwPoA5pd0ZCRMkXrxXGsV3bG3fRYCOSrPlXW
         Gwj9JVX9QKjH5rCO1xYOTI3NHvoNTwR4SvsDuQffdCcWacYkB7IpvBKpInRx1Kofabgh
         aOMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:to:cc:references:from:subject:message-id
         :date:user-agent:mime-version:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IWpvnK8/ZB7HsPaYnO4waIX/XExFp9sISfvHE+I99Vc=;
        b=oa4gjMbX2EFiAd8cwvqUSRUjxT3b9iHTiSIgFpQIlS4Tt3LxzQifnWtcpYyMwnBzrT
         7LAjEcIZLwDbu2aQfd9hugcOBToS3eW8FWTHwp90BRv+3l0wFBPv1K1Zna/fBmijstlG
         I69I8Awhv62vSgbRvZro2niIUTpqcRXZNGQwyc/a3uDob6moKJBSe/RovbcYh4TTjB9V
         7hs9XCyyzcGa8V1kEoPdek7sJuLGXT3wpDVAgLS8u/fsVrM1OXFS3kWt5nL9p9SBbAYh
         ipoOB7bOfJQ5Vkt21GnXVOopD+w1ChFEKvleqydnCag/PG+ny5p1/sbf5S3cUDuvByMh
         jWcQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533WzB4jq1lBjIh6xlF01YFyWiw6EknQrVT11TjeKN5wYQt3s9BD
	T4S9JEt39ePplqK3wx3w7wM=
X-Google-Smtp-Source: ABdhPJw/ciQmeBIdTSSjiRlE+9ynQASFfzRfaHQ7pJOzb8UQh87f15an6Epk5/Z+GyzSgu0EYcpzOQ==
X-Received: by 2002:a17:907:2658:: with SMTP id ar24mr20579328ejc.329.1631996544130;
        Sat, 18 Sep 2021 13:22:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:c258:: with SMTP id bl24ls4996401ejb.6.gmail; Sat,
 18 Sep 2021 13:22:23 -0700 (PDT)
X-Received: by 2002:a17:906:3148:: with SMTP id e8mr19311147eje.240.1631996543202;
        Sat, 18 Sep 2021 13:22:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631996543; cv=none;
        d=google.com; s=arc-20160816;
        b=uBCir+vYpu5sZRtiIaw+Dky5bfwXohgAIsWxA2d2LjV+ETBrjnqDVK6dWWvADj8Gw2
         9dBdDfG3VXwGbTrYUj8caoyUqAYkTZhqOa9fMNTZ8YxB4siCfh3yw1hsXYjcW/CGYTy1
         /YxUwUJAgwlGtUtXkGZvwZIdeEOTcekSCjc2zxiCtJEK+yd7VBipQuQksOwDAvhaaKVW
         mA2IJq+tk0E0vKXjkWdV1fpWVMevZiMYE6Q3Qb7/TyGsD39HXKSNrd6tT7V+TBKyZCm5
         wB19UCL4iC0KlsjBMeljQ2eN6+NcDabSQdy366pdWPMw4Vn7Nx4tOW/Q3eEFsFayzqWq
         bdYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:mime-version:user-agent:date:message-id:subject:from
         :references:cc:to:dkim-signature;
        bh=SpkxL4+QZ4om3Q/rDebiYjm26W4FLafWIJIPJJdk1/Q=;
        b=W/wbznxlWbTT0ufWaL+d0AK2GKeCE3Hxd56Yd2vkkJOqD+iQYdg41UrEC0x1g1EMqO
         jfmF1zMCrnhgWJRxWsptf/Cg9j9h9yHZy/sfKyg4lGR9EW5ydlra2DzwEAfQnKnZmrPP
         89AWS0vpMBlOX3fY/vfAgdZLM7+LezDw/mq/RQsYvVSnSeY5gKFGzDfROjweOTojRgGj
         jrKA7FroinBNyqTqys2nl/ESaEPsZ42EW9dlqc0BhTCKYUzfuf43TpBONRi1ygiiqUkt
         i3+zes/L2ZjrpaMHlHFz/6VuncAXgqK9qAevW8aMYqBsk/ottMtCy3R35l2s21gQQYcQ
         o/0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alexander-lochmann.de header.s=key2 header.b=khznvf5Y;
       spf=pass (google.com: domain of info@alexander-lochmann.de designates 185.244.192.111 as permitted sender) smtp.mailfrom=info@alexander-lochmann.de
Received: from relay.yourmailgateway.de (relay.yourmailgateway.de. [185.244.192.111])
        by gmr-mx.google.com with ESMTPS id p21si825789edx.1.2021.09.18.13.22.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 18 Sep 2021 13:22:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of info@alexander-lochmann.de designates 185.244.192.111 as permitted sender) client-ip=185.244.192.111;
Received: from relay01-mors.netcup.net (localhost [127.0.0.1])
	by relay01-mors.netcup.net (Postfix) with ESMTPS id 4HBj0t4VCdz7xDT;
	Sat, 18 Sep 2021 22:22:22 +0200 (CEST)
Received: from policy01-mors.netcup.net (unknown [46.38.225.35])
	by relay01-mors.netcup.net (Postfix) with ESMTPS id 4HBj0t4591z7xD3;
	Sat, 18 Sep 2021 22:22:22 +0200 (CEST)
X-Virus-Scanned: Debian amavisd-new at policy01-mors.netcup.net
X-Spam-Flag: NO
X-Spam-Score: -2.901
X-Spam-Level: 
X-Spam-Status: No, score=-2.901 required=6.31 tests=[ALL_TRUSTED=-1,
	BAYES_00=-1.9, SPF_PASS=-0.001] autolearn=ham autolearn_force=no
Received: from mx2e12.netcup.net (unknown [10.243.12.53])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by policy01-mors.netcup.net (Postfix) with ESMTPS id 4HBj0r4q5xz8sX7;
	Sat, 18 Sep 2021 22:22:20 +0200 (CEST)
Received: from [IPv6:2003:ed:7f18:38f0::67] (p200300ed7f1838f00000000000000067.dip0.t-ipconnect.de [IPv6:2003:ed:7f18:38f0::67])
	by mx2e12.netcup.net (Postfix) with ESMTPSA id 1E8BEA0591;
	Sat, 18 Sep 2021 22:22:18 +0200 (CEST)
Received-SPF: pass (mx2e12: connection is authenticated)
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
 Andrey Konovalov <andreyknvl@google.com>, Jonathan Corbet <corbet@lwn.net>,
 Randy Dunlap <rdunlap@infradead.org>,
 Andrew Klychkov <andrew.a.klychkov@gmail.com>,
 Miguel Ojeda <ojeda@kernel.org>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Andrew Morton <akpm@linux-foundation.org>, Jakub Kicinski <kuba@kernel.org>,
 Aleksandr Nogikh <nogikh@google.com>, Wei Yongjun <weiyongjun1@huawei.com>,
 Maciej Grochowski <maciej.grochowski@pm.me>, kasan-dev@googlegroups.com,
 linux-doc@vger.kernel.org, LKML <linux-kernel@vger.kernel.org>
References: <20210326205135.6098-1-info@alexander-lochmann.de>
 <CA+fCnZcTi=QLGC_LCdhs+fMrxkqX66kXEuM5ewOmjVjifKzUrw@mail.gmail.com>
From: Alexander Lochmann <info@alexander-lochmann.de>
Subject: Re: [PATCHv3] Introduced new tracing mode KCOV_MODE_UNIQUE.
Message-ID: <aaee2292-022b-d99e-9fa9-b48ad5c2fe92@alexander-lochmann.de>
Date: Sat, 18 Sep 2021 22:22:17 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.13.0
MIME-Version: 1.0
In-Reply-To: <CA+fCnZcTi=QLGC_LCdhs+fMrxkqX66kXEuM5ewOmjVjifKzUrw@mail.gmail.com>
Content-Type: multipart/signed; micalg=pgp-sha256;
 protocol="application/pgp-signature";
 boundary="jeoiCDS3Yo1W8TmZdEkFUwrpjDXm41xxy"
X-PPP-Message-ID: <163199653879.4199.11228245821604856147@mx2e12.netcup.net>
X-PPP-Vhost: alexander-lochmann.de
X-NC-CID: ldOtAIRfa6FXYg/2lhJBu0h6e2ToKhuNgU4pdNS2aPCKFwbzmIdRzZbn
X-Original-Sender: info@alexander-lochmann.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alexander-lochmann.de header.s=key2 header.b=khznvf5Y;
       spf=pass (google.com: domain of info@alexander-lochmann.de designates
 185.244.192.111 as permitted sender) smtp.mailfrom=info@alexander-lochmann.de
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

This is an OpenPGP/MIME signed message (RFC 4880 and 3156)
--jeoiCDS3Yo1W8TmZdEkFUwrpjDXm41xxy
Content-Type: multipart/mixed; boundary="ijdinWyZS3cUUOiSvgMUkUAuSPyavspzk";
 protected-headers="v1"
From: Alexander Lochmann <info@alexander-lochmann.de>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
 Andrey Konovalov <andreyknvl@google.com>, Jonathan Corbet <corbet@lwn.net>,
 Randy Dunlap <rdunlap@infradead.org>,
 Andrew Klychkov <andrew.a.klychkov@gmail.com>,
 Miguel Ojeda <ojeda@kernel.org>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Andrew Morton <akpm@linux-foundation.org>, Jakub Kicinski <kuba@kernel.org>,
 Aleksandr Nogikh <nogikh@google.com>, Wei Yongjun <weiyongjun1@huawei.com>,
 Maciej Grochowski <maciej.grochowski@pm.me>, kasan-dev@googlegroups.com,
 linux-doc@vger.kernel.org, LKML <linux-kernel@vger.kernel.org>
Message-ID: <aaee2292-022b-d99e-9fa9-b48ad5c2fe92@alexander-lochmann.de>
Subject: Re: [PATCHv3] Introduced new tracing mode KCOV_MODE_UNIQUE.
References: <20210326205135.6098-1-info@alexander-lochmann.de>
 <CA+fCnZcTi=QLGC_LCdhs+fMrxkqX66kXEuM5ewOmjVjifKzUrw@mail.gmail.com>
In-Reply-To: <CA+fCnZcTi=QLGC_LCdhs+fMrxkqX66kXEuM5ewOmjVjifKzUrw@mail.gmail.com>

--ijdinWyZS3cUUOiSvgMUkUAuSPyavspzk
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: de-DE-1901



On 27.03.21 15:56, Andrey Konovalov wrote:
> 
>> @@ -213,9 +223,10 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
>>          struct task_struct *t;
>>          u64 *area;
>>          u64 count, start_index, end_pos, max_pos;
>> +       unsigned int mode;
>>
>>          t = current;
>> -       if (!check_kcov_mode(KCOV_MODE_TRACE_CMP, t))
>> +       if (!check_kcov_mode(KCOV_MODE_TRACE_CMP, t, &mode))
>>                  return;
> 
> mode isn't used here, right? No need for it then.
> 
No, it's not. However, check_kcov_mode() needs it. Dmitry suggested 
passing a pointer to check_kcov_mode(), and let the optimizer do the rest.
>> @@ -562,12 +576,14 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>>   {
>>          struct task_struct *t;
>>          unsigned long size, unused;
>> -       int mode, i;
>> +       int mode, i, text_size, ret = 0;
>>          struct kcov_remote_arg *remote_arg;
>>          struct kcov_remote *remote;
>>          unsigned long flags;
>>
>>          switch (cmd) {
>> +       case KCOV_INIT_UNIQUE:
>> +               fallthrough;
>>          case KCOV_INIT_TRACE:
>>                  /*
>>                   * Enable kcov in trace mode and setup buffer size.
>> @@ -581,11 +597,42 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>>                   * that must not overflow.
>>                   */
>>                  size = arg;
>> -               if (size < 2 || size > INT_MAX / sizeof(unsigned long))
>> -                       return -EINVAL;
>> -               kcov->size = size;
>> -               kcov->mode = KCOV_MODE_INIT;
>> -               return 0;
>> +               if (cmd == KCOV_INIT_UNIQUE) {
> 
> Let's put this code under KCOV_INIT_UNIQUE in the switch. This
> internal if only saves duplicating two lines of code, which isn't
> worth it.
So. Shall I skip the fallthrough and move 'my' code upwards?

-- 
Alexander Lochmann                PGP key: 0xBC3EF6FD
Heiliger Weg 72                   phone:  +49.231.28053964
D-44141 Dortmund                  mobile: +49.151.15738323

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/aaee2292-022b-d99e-9fa9-b48ad5c2fe92%40alexander-lochmann.de.

--ijdinWyZS3cUUOiSvgMUkUAuSPyavspzk--

--jeoiCDS3Yo1W8TmZdEkFUwrpjDXm41xxy
Content-Type: application/pgp-signature; name="OpenPGP_signature.asc"
Content-Description: OpenPGP digital signature
Content-Disposition: attachment; filename="OpenPGP_signature"

-----BEGIN PGP SIGNATURE-----

wsF5BAABCAAjFiEElhZsUHzVP0dbkjCRWT7tBbw+9v0FAmFGSnkFAwAAAAAACgkQWT7tBbw+9v2N
2RAAzeXvASCTHMOY9leID0oi73MODfrY4EW74Jq2CnbtM+lj6FjzL5kCGkILz5LkSuF5FNsY2zdN
sYeb6fK6eIIvlSSdHOn4v22lFRrHNP2VOE6ExAZCve8hcw7GlTtSBEGZcHIz4wL2i2A2jNn+furn
eQLdujoaYQ7keOck/fxVdexQZ1JxE/42VLR/R0yG90/EZLkn/0N7iaQ2jm1XQjtVdV9VkI8xxFwy
bvyXxRSsmxCHJ8m0GNQY6Jdy6f/wPg2/1hGSAOzZXsh+V0R7azpGh9oLCrECWYZWyyqO85SkGs+m
LuB3urCeMZVMHci1NccR3hiYP6Ma2B09G+m/inEdU/cf3YdzSoZ/FbqRZO2GenmkvwK5Xv03hdzb
wgEUBTbSBpD7I4EIuS/eCjsESGCeToFeG9GKhurtzDg4woustiuXkb/S8xP42C+LhXoApAz1yvaF
Son/f0gS9WzcbQSUxPM1AHE/Flq6B0P0lYAW9906b0aFwHzFW1UHIMzzwhbLJNvFJOb6F/BvtrMy
LFnp2WqL8xR+oPOXiBPWMkn8OU1pwQtJkwFWyaAlGImJdrcBNrd/qDsYnJF69jK0knIAtEvWAJGe
cHNX1Pe0/fMska+6bhPUV//2w/dnLHjP5SAlazjFKReZ2/MyujJ0YOtElvckvj3G8MIh9Lu97eye
KiI=
=oZeu
-----END PGP SIGNATURE-----

--jeoiCDS3Yo1W8TmZdEkFUwrpjDXm41xxy--
