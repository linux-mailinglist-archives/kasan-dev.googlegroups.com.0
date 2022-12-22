Return-Path: <kasan-dev+bncBAABBKUQSGOQMGQE2ZGXMHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4281A6540AE
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Dec 2022 13:06:04 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id s12-20020a2eb8cc000000b0027f6f40eeb3sf415894ljp.2
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Dec 2022 04:06:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1671710763; cv=pass;
        d=google.com; s=arc-20160816;
        b=U3yyCPcGEuejvHzuXYT0zntjdxeSEEkxLf3VmYh2gHsCdOAmjmE/+6sDWBcIVV+m/c
         oP6QCX9l5ZhDE+u5JVQCAGL9lPZXEe5KKCphe1HLJCVTeL60gOf2xEh1j14O/8+3xS+n
         uYAWCNm/jX1WlUUwVm6+laISsbC0+Mam9NqQ6fpjRisXY6HvLgLVpDs8eWH2dJQq5a9G
         664WrkfxmEkVKcymqBPKvLFIx2pzRDJl0PRkxcyjYBVBf/axGU2n3oeXMrEI2Elp1jUj
         pFfkHMpdmS23l+E/tuue26QGmx72dVzsUaWSYOwvAvwcjFNtQg5BSCc7plEFz20lxzvM
         sDOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:to:from:references:cc
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=FTejLCr3SMGiOqLufNKQfa6qODWbbl90oWtxig+iwwk=;
        b=Kgk9Mz7KLh/t7lMQiXiGc6sxIZL/xTd5KhQWlxnsvO6+E8tx21G7U+004RwPrPhfhm
         GbdGmIoCL4QRRuIWMfCOsD2U+veQTqDQ4vyzZeJQLh8P/3djhyRelIlkeRQuzyqKMKFK
         uSEXU4Y8TS8vz5u6AA66ktFzYkVrK0JuWVrDm7FCHLe9dNGfHJt38vCXxuOY5jsJNpKg
         XXSfr/tLKyVdBGDxaTOUf0l/L2PD5MrZbQE4oSCv4pUwaKUiINGLHOj1ceZiQoxoUwiD
         YQACYeC0GKrEVxFC5hStSt2MDauU0xbJsYSuiigtT65UnvbvZvmH1lAtq4bzxsuS7A2V
         Uwfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of regressions@leemhuis.info designates 80.237.130.52 as permitted sender) smtp.mailfrom=regressions@leemhuis.info
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:to:from:references:cc
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FTejLCr3SMGiOqLufNKQfa6qODWbbl90oWtxig+iwwk=;
        b=FuGgXDQpq1LUqv+cLN981m6SIQkV7uoytt1xpc8nWmKT2ZnxYkcUEMI1MVRC+8g/Dl
         iTJwl+JgGJo53M6s1UW0rwa3j/kQUCjoIYuDG+sVny2vjXmYlfwY0+e2/fhVc3dhqFIo
         nN5iuk5d94orSg1GrGw80zmmRkYqf2yMI2W1CNJnAOGbKxsG/EJfK1D/FlAat2RRSUGW
         VPgYldoUPTDY75mPvB38wBWTHvw2SFFW2ZI3MSpoRYQQGStVf4/FNwlhqGvDPLl2iJC0
         LqtkZgG8k0aFJymmnM4vedVgKLPRt5WlqGixG6jN0sys9mkOunb0PIZD49OVtoQ1oJZ1
         Uyng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to:to
         :from:references:cc:content-language:subject:user-agent:mime-version
         :date:message-id:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FTejLCr3SMGiOqLufNKQfa6qODWbbl90oWtxig+iwwk=;
        b=xpC0X5BGUpq25tFmQRYfNd+3hvd9SpIeX4iri8DZtdM2/gJA9ZzYyQ2e+/qR/xbJF0
         wUoRakvmafly31DcNsEoT66pKWpxm35IZbRZHPl5pf+2flz0wy432s4HcvAbEIyAP9Zx
         v+e78jLpL02euPgyoNrsagYYw/MUdJLH1ZBTbT6c20RL6gs5W4Jmuiyb7xeZBjSH93TH
         7YMgmRTaCGKEiYUJOpxDKKklT6FHTXDoN725KmVakVFdCMVvJ2jkwN78gB1ZYdwBpzmO
         oJp9Y71InUYwVK7vwLNW11Kx6R3IcmiLg7wwZ5DeUWyhNsveCKQlvDmVkFQ3VR+YgI1u
         2rJA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kriFbG4Uo+FpQGx65hLAseF0rCckKqQZf912bO4EEDTduZoDDui
	hZdKagUwp6nJ/huFqYpnnLQ=
X-Google-Smtp-Source: AMrXdXt9XaS7+Sjs8qRTypXqBg2Uk1NQ96l3Q8kb4BrWk4elRp4DF4pXBdzqP0jYXBiBB2/W+UbuoQ==
X-Received: by 2002:a19:a415:0:b0:4b5:2f4e:a0cc with SMTP id q21-20020a19a415000000b004b52f4ea0ccmr670389lfc.392.1671710763440;
        Thu, 22 Dec 2022 04:06:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1182:b0:4b5:3cdf:5a65 with SMTP id
 g2-20020a056512118200b004b53cdf5a65ls1271393lfr.2.-pod-prod-gmail; Thu, 22
 Dec 2022 04:06:02 -0800 (PST)
X-Received: by 2002:a05:6512:304a:b0:4aa:54a:3a6e with SMTP id b10-20020a056512304a00b004aa054a3a6emr1964618lfb.41.1671710762370;
        Thu, 22 Dec 2022 04:06:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1671710762; cv=none;
        d=google.com; s=arc-20160816;
        b=r68OfTamg48pi7Dvj1hVuAi0eMmOVKppH6InrIT/s9RZhZQIeIBf0rg/pa72F3UWhA
         eZP2mPHjQpJVJUroWqQ02bb+PEPjDxBp7IBP5vbKbPb3Cf8GmuZlAlWXjQYDqigXmZuR
         JnNOlX7ZuvDCJmQJABQOqcT2m6NIutjc19Uhk8E7KMvFWZ9TTj1osT6Qb/i1Ym+6nD5l
         dT8ZHGv7HdQfIUZYZ2kqg4ukWCTSeKN07sl52uSbrMiefO+jlZdCG4bG6KY89gjJszD0
         0cv3O6EvxGFxA3JxMTdPGazzVwZvKiVLLunmNi6TSaB9GUYZjMt1oND7T+IYSzGmVxFb
         WwYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:to:from:references:cc
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=7u/9R8ioCeKW5p8an54uvxfXwO8qantpGQfpvA8dFhs=;
        b=kGCxu/sFPFUngPCxwcQNl4JPdMa2k8DMZrPWt644mg+bMZUto9aQ/wFuR8g7NhG6EN
         b2Wv/YcBJIOBZvxeqlYfgKvAnf4lPPX7kzMW4yQTI9L6jrg5U/KfZxQM539j0Y5fpEKD
         IURwOUISrkHzenYEiqKb0pFhRS/cI1bB8Is36+N68IIgaj0FZUeEXZYrU3X+qw0EToOF
         ThmI6j4YB3Tg7CX1iXyh08Ag4ildioD4goLeRvLBsiWhIZtDOJFROASdnOffJt0MtjwD
         qr0jo6sjJ8g4kefoUwBoJ8+3IKycG88SAYYJI06/dBwuZupwynveL9WpFYAN85bDs7K2
         NdtA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of regressions@leemhuis.info designates 80.237.130.52 as permitted sender) smtp.mailfrom=regressions@leemhuis.info
Received: from wp530.webpack.hosteurope.de (wp530.webpack.hosteurope.de. [80.237.130.52])
        by gmr-mx.google.com with ESMTPS id d17-20020a056512369100b004b4b3e2e283si20316lfs.13.2022.12.22.04.06.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Dec 2022 04:06:02 -0800 (PST)
Received-SPF: pass (google.com: domain of regressions@leemhuis.info designates 80.237.130.52 as permitted sender) client-ip=80.237.130.52;
Received: from [2a02:8108:963f:de38:eca4:7d19:f9a2:22c5]; authenticated
	by wp530.webpack.hosteurope.de running ExIM with esmtpsa (TLS1.3:ECDHE_RSA_AES_128_GCM_SHA256:128)
	id 1p8KKn-0004Lk-6t; Thu, 22 Dec 2022 13:06:01 +0100
Message-ID: <962eff8e-8417-1096-f72b-4238ca4b0713@leemhuis.info>
Date: Thu, 22 Dec 2022 13:06:00 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.5.1
Subject: Re: mainline build failure due to e240e53ae0ab ("mm, slub: add
 CONFIG_SLUB_TINY") #forregzbot
Content-Language: en-US, de-DE
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org
References: <Y5hTTGf/RA2kpqOF@debian>
From: Thorsten Leemhuis <regressions@leemhuis.info>
To: "regressions@lists.linux.dev" <regressions@lists.linux.dev>
In-Reply-To: <Y5hTTGf/RA2kpqOF@debian>
Content-Type: text/plain; charset="UTF-8"
X-bounce-key: webpack.hosteurope.de;regressions@leemhuis.info;1671710762;1054d6c9;
X-HE-SMSGID: 1p8KKn-0004Lk-6t
X-Original-Sender: regressions@leemhuis.info
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of regressions@leemhuis.info designates 80.237.130.52 as
 permitted sender) smtp.mailfrom=regressions@leemhuis.info
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

[Note: this mail contains only information for Linux kernel regression
tracking. Mails like these contain '#forregzbot' in the subject to make
then easy to spot and filter out. The author also tried to remove most
or all individuals from the list of recipients to spare them the hassle.]

On 13.12.22 11:26, Sudip Mukherjee (Codethink) wrote:
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

Thanks for the report. To be sure below issue doesn't fall through the
cracks unnoticed, I'm adding it to regzbot, my Linux kernel regression
tracking bot:

#regzbot ^introduced e240e53ae0ab
#regzbot title mm, slub: CONFIG_SLUB_TINY causes various build errors
#regzbot ignore-activity

Ciao, Thorsten (wearing his 'the Linux kernel's regression tracker' hat)

P.S.: As the Linux kernel's regression tracker I deal with a lot of
reports and sometimes miss something important when writing mails like
this. If that's the case here, don't hesitate to tell me in a public
reply, it's in everyone's interest to set the public record straight.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/962eff8e-8417-1096-f72b-4238ca4b0713%40leemhuis.info.
