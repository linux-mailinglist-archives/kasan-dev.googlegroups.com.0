Return-Path: <kasan-dev+bncBCG6FGHT7ALRBWN5R33QKGQEOWZJHKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id A96001F7ADB
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Jun 2020 17:27:21 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id c12sf2803416lfk.12
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Jun 2020 08:27:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591975641; cv=pass;
        d=google.com; s=arc-20160816;
        b=IY76XpQSB3bHZRTB6Z7RaiO/0gqqhCDMT7JFWcJDNdOXq+yGSBzlbFPJDy5DEaEXAt
         nwHFpotdqmP8Cno7qbyA8/giHc9Z1gDhXiueBklJXppOjNsm5qc64gC1g5ouWWBTj718
         5i2CEu+jeTrL9Sc3Y/gd8SIj3E6EMOC0AO3MKiIvVzLgXqNcjcYBjdBQvS5CcvjHccGM
         ea0Sp10QazXZuJxUEH/PukngzMpHgHSkeS2Kq64hzZR/NQFLLa6vEEuoQpEkeT4cBN/P
         X4h3c2m+lCejTGAkuO9JJ0n7AXy8Ufw1AmSWiny1sAapsJv4Yf7vlXsV1aopMIsj9ICM
         /TOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=OK3iCKEU4HPJioQu5TCLElrazIg7/685MgnNWxspdGQ=;
        b=P9CQoCJkt/aaPf7o3d0vdAW/idCSHk+4ZMu3HKUDjCL+7rpLWGkUbDsW9Q24G0yEXF
         gw8GC85L7X31HPvxYzHQTFTXPxosfm9XN1FKbMf76sckZX1Fi8Xyy/xn5539mg+zZZYj
         frxWnMzFdjGpiBeWeYqyWFHzQIhb6owTu2x++R+PxchuwkT/Wfr1ldcGyTiiVZmJtkcY
         dJNvMFMNOEwx67qrAEUVB/sDOViLghy2gEguXvxK0yTk104jwrgQQJa4fj6dDL3PEhwh
         qIpIXKZkOs6rbNdTk/306QryEL8NknUaN6Cq/giStDRix3p0vXvaaSE/OISagKGh9qVw
         CP+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mliska@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=mliska@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OK3iCKEU4HPJioQu5TCLElrazIg7/685MgnNWxspdGQ=;
        b=nHJ1E2bOvmznchKXaVkEH+I8L4RFfTmU85FiyPf34vhelsqFNkDjlUWAnSvhPJDotr
         +9t+s5z9uSgd/UWuoMALUfi522oJ3NmOWn3N7mrvgnmFu//ulyDKGD0r7wY+E3O70A6g
         QCY1GvmahCBwJmlCyiwhcfNSBQZQ3WCGgIq0oDZS5iHjNGxwnCLJfk34gSlOxW3dmc2l
         I3Q4Edf0vF3AA6iB5oeUuz83Pj9QKhz9kZpLb5cT/66gh0dMK1zn84LMSSfZ54mY/Rk6
         Srw4GboTlvQpmuESvWruO+KvbvLGinMcGl2DZXwcFg6GABN33lraVNS+4Krdemf1kVUH
         eejw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=OK3iCKEU4HPJioQu5TCLElrazIg7/685MgnNWxspdGQ=;
        b=R9QTsTu8bFvFZdPGFUeOv9/tbAF2ftMHqgXOnwRjlGvQ3N/m9K4rZ4OS3dqjhKWzIp
         T+MqRaF0mt+oNQt6+fOnzY2m9BXPSbEpxrIwiThHHzWYmKN+shu/BitiSOrbA2PEjtPr
         l5B2wNwnid6RPSRyJ9KS9NTH3jzw2wT20iUrl0EpdlAUX2XQEBSZJX64Y3xwyH+jqqXx
         AC9yVG4V64IP/vWZTU+eZjCfDtELcMYTboqu9ygGZ1FgfX0f7UfCP7L85s+Ciov5/mA8
         s37OuUN1asNpa7upJbiQACpIpJry/lzNhA5lFKtvw4KfGMSB6+D0zq2GMrVmvMV5mQ7u
         RpMA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531qE8Ti9SRCkJM73dfrhO7+9A2VL9bmiCJl27igfU+oOSa9/q42
	I2E3yXhWFbu7yirh7dAfPok=
X-Google-Smtp-Source: ABdhPJybcp+i/XH08xXAW6FDMYgNbiXe3SrCHVPUGXqdulflFToYUl/gEUJmJEOwn4t/RvvQ8BqyJg==
X-Received: by 2002:a2e:b0e3:: with SMTP id h3mr7676837ljl.16.1591975641197;
        Fri, 12 Jun 2020 08:27:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9718:: with SMTP id r24ls1292788lji.3.gmail; Fri, 12 Jun
 2020 08:27:20 -0700 (PDT)
X-Received: by 2002:a2e:9d48:: with SMTP id y8mr7151590ljj.419.1591975640648;
        Fri, 12 Jun 2020 08:27:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591975640; cv=none;
        d=google.com; s=arc-20160816;
        b=qMrS/ttbgw4zKR5NmVKvaqDoB+CBhGEoTsMdKi2JWPvVS7xN0dmNriGODVIEHUrNxz
         SbeICcy0dmoRaq9T5phdA6iP5Smh6tBQ/dzvPnjPMYqud06s5Ga5ivbY1hOGFnANisAi
         GXzz4F+0OS4uyt+RqKm4ZdIIZHu9RBg7vr+bp33MkDobxdOiabERF+BKQBq2/6rQXtfV
         pzo+iIGvq5dupj44dD3K02DjNErt9ua17KaClWRy7LfoM2thZZoTmZglDCzRwBWNU/Pf
         kcnsrM5P3jrLNKB8iYAG/sQDxkvG1eM8QI7s0D8RQZTCkpQqlrjwKs8t0QNdsMnBEZaO
         qcZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=O0TpoxuN9F3MhpumUttVrmFmfJfMIJUj61RqcD78IKo=;
        b=K7yAxWSB7ahnogyAaYJGDaGVk3TfluT3Stqtw/7R3LB59/9attHF/P8sQS1tx+ZIbw
         XFtBVinWOQGpUfi83c+POOU+v/dBEbT1zRoYu534LVEM3zbV3QFHh61eEpweZqPlUWr8
         NvmwjKNr0iuRf3xNUovLqmMx5EKoHmrLDqleJi8YUWF4UNiWuw3psr9dh3K6XbcdJtj2
         J2rAcvXVYWQLtw2Cq7gamd69W7n9TBFojic1rZIpUtuW7k9HjeiEcXHT/mjtoSItgj6j
         7nxJ3OCwDammIyOfv/SWE+/DVj8xqUcX+WdVghRkS9Ny949al85xVHlUi+nn+1HufSJS
         uYaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mliska@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=mliska@suse.cz
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id r21si449678ljp.0.2020.06.12.08.27.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 Jun 2020 08:27:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of mliska@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx2.suse.de (Postfix) with ESMTP id 52490AAF1;
	Fri, 12 Jun 2020 15:27:23 +0000 (UTC)
Subject: Re: [PATCH v2] tsan: Add param to disable func-entry-exit
 instrumentation
To: Marco Elver <elver@google.com>, Jakub Jelinek <jakub@redhat.com>
Cc: gcc-patches@gcc.gnu.org, kasan-dev@googlegroups.com, dvyukov@google.com,
 bp@alien8.de
References: <20200612140757.246773-1-elver@google.com>
 <20200612141138.GK8462@tucnak> <20200612141955.GA251548@google.com>
From: =?UTF-8?Q?Martin_Li=c5=a1ka?= <mliska@suse.cz>
Message-ID: <966abdc1-23c1-08dd-87e8-401ead7a868b@suse.cz>
Date: Fri, 12 Jun 2020 17:27:18 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.9.0
MIME-Version: 1.0
In-Reply-To: <20200612141955.GA251548@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Original-Sender: mliska@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mliska@suse.cz designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=mliska@suse.cz
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

On 6/12/20 4:19 PM, Marco Elver wrote:
> On Fri, 12 Jun 2020, Jakub Jelinek wrote:
> 
>> On Fri, Jun 12, 2020 at 04:07:57PM +0200, Marco Elver wrote:
>>> gcc/ChangeLog:
>>>
>>> 	* params.opt: Add --param=tsan-instrument-func-entry-exit=.
>>> 	* tsan.c (instrument_gimple): Make return value if func entry
>>> 	and exit should be instrumented dependent on param.
>>>
>>> gcc/testsuite/ChangeLog:
>>>
>>> 	* c-c++-common/tsan/func_entry_exit.c: New test.
>>> 	* c-c++-common/tsan/func_entry_exit_disabled.c: New test.
>>
>> Ok.
> 
> Thanks!
> 
> Somehow the commit message contained the old changelog entry, this is
> the new one:
> 
> gcc/ChangeLog:
> 
> 	* gimplify.c (gimplify_function_tree): Optimize and do not emit
> 	IFN_TSAN_FUNC_EXIT in a finally block if we do not need it.
> 	* params.opt: Add --param=tsan-instrument-func-entry-exit=.
> 	* tsan.c (instrument_memory_accesses): Make
> 	fentry_exit_instrument bool depend on new param.
> 
> gcc/testsuite/ChangeLog:
> 
> 	* c-c++-common/tsan/func_entry_exit.c: New test.
> 	* c-c++-common/tsan/func_entry_exit_disabled.c: New test.
> 
> 
> -- Marco
> 

Do you already have a write access or should I install the patch?

Martin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/966abdc1-23c1-08dd-87e8-401ead7a868b%40suse.cz.
