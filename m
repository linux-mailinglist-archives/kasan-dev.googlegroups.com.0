Return-Path: <kasan-dev+bncBCAP7WGUVIKBB34G5CBAMGQEU2NMMUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3683734623E
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 16:04:17 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id z21sf2284550pjr.9
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 08:04:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616511856; cv=pass;
        d=google.com; s=arc-20160816;
        b=UedBqVzlcDLF/IXdtEHSoRMXzyjBN6/7V1Gi84KfwkrQxrx9KbCvESzkKsApx0bF/m
         VY1rSujzMkKEZg44sT/FMKAJ9SV88TeYvkYeWK2uBi/Ymcq0ynKmprMcyIRNvr/0wnQz
         QZcQnt3ZIRQEUrtF7u6A1jqb3LuAtSs+6n6xIPeprM3jXKKT4d4Vs3ue2/T0sZOd3V1e
         YgDgd9UBvFQtyS43uMlTp0AMPllSovD1v/mo54xpWt9V92QoZNL7SpRnTA06PdXZNbpp
         43BwqeGBd2xNpEKAXkvZxQOveiyeZixXnYeFt2Z3bqGfX9+XYAUb3YoqtVkVpArbw3D/
         6lmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=U8shdoPMBw1YUh8kiLbRIh9zptdJM0VRStZP5KOSwao=;
        b=D56VmeroZtgUieLftUykwujS9emsr6trWn7w0WHHmjdR+1OAR0ehTtVhaUBjUN4TJS
         qdC/uPd0MlYj+4vo6bqcNQl4ZUhEPq/wGOrP2eYAudmjbPFYRy+XD9Es2lNEUwQX8YjF
         nIq7QsZXglB3P2O28uUhRzHlGJgDFP7+VGoR18lOG41LHLXMBX/14/YzBX5IYR14En5n
         B4kVQiHCtAp3RSKt6XR/sQ7AzN5rRlLy0NKhNZzneMjbYJMSjVReIGYLUNb9i+IGr+nU
         G6kiRlIqYLkZN/s4a11o8psAhQjjSQa18wVDGLtBCGrX0GrDdKOPPalcMzkv54wSS2Hc
         AQ8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=U8shdoPMBw1YUh8kiLbRIh9zptdJM0VRStZP5KOSwao=;
        b=kpnxmxb+7O0un/cOSOJ2VLbtdidk+XKrqKkF48Gg6TthHW/LuSm9dwOyeSSbjgmq3G
         wyPKLciAaBaFjh1SLBLHkFyGtHwUEbxW7Hrml8yD7OLYzqXf0f82ooE15JTUFfI6ekM2
         0JbQNoFrWq9bHzCeUHyzNKOBb7PSS72ARtgRogGczDWQdwHaS1tTrzlEoUfjWP65fR7M
         FkflNjTyCTm5t5zh1BJDLv8SgCZFhP9d3Zzj5NE8V3JmHMBi+FiTDD54YgPUlMPSrI2h
         9UoXSly6vl+MG0s7H7MmOQuVvYEr+ybCvO/oTPuJPi0/jDL8L9gq4i4UAIYHYI0M3NBM
         YE8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=U8shdoPMBw1YUh8kiLbRIh9zptdJM0VRStZP5KOSwao=;
        b=UeZSLiyvWFVpEobDyZp15F/cMUclwwYvoYH/DO7ynDlyJjSSSWz5vhKbMU87tiBvlS
         FeNsnQLvEMh6BhRkyT7NiwZVXAR+L7dePFyXcAWKr0WnFBZz/btyiPQIU7DE9rLOJzHq
         m+9C1oOrVostkyw2zMtrNHUuwl8bgJMpvwDqspkhGzRJillbtgm9O9SzV05o/kFyREDm
         8fYpp5OLyTdpFN59vvQ27ELj3t3WKaFqb5LI5aGNfpHZiGUTxkG0DBdlqrPp5PMmp1oy
         YTlT0gT7DM52wkwlym7py6bpHTKSFR/HTb2iXGGqby6BVLZfgUzh1dyunRJm8OUAqYWB
         r1Tg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532tN+p2kxEhqgamj9BkjU3dkjAa/bGtmIPIWBHDXE429m0NfRqM
	k9KLyosCqWeEsr/iYmLYgGc=
X-Google-Smtp-Source: ABdhPJz+nxOdj87xaYIEmHyQSuarbbRSdlU88hZj4ySlF2ik5dFaIkH6O90g+i4tUEZLv8p8cHm3LQ==
X-Received: by 2002:a17:90a:f184:: with SMTP id bv4mr4746721pjb.43.1616511855897;
        Tue, 23 Mar 2021 08:04:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4d43:: with SMTP id j3ls5670758pgt.1.gmail; Tue, 23 Mar
 2021 08:04:15 -0700 (PDT)
X-Received: by 2002:a63:4845:: with SMTP id x5mr4180792pgk.315.1616511855360;
        Tue, 23 Mar 2021 08:04:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616511855; cv=none;
        d=google.com; s=arc-20160816;
        b=zaAX9X6l2WSxm9YB27vsCopZt0BuaKhCLpJeJiHSAZgL34eVxb5Xlwf7ixnzj85m3x
         uvOXn6ASdJxmEZqoYyUxJsrHjP9OoeZbSpS7a1vt3EInd2QwVreuH3yO3UYNETbFdK1H
         ugi9/hs9gkf3ng+7D9a882Mrco6a5ys9RtYZLzGhQZ+OKlir0tvfa8HzeavXbM7f4taG
         ua70g5ybagtQC04/d2cYEEsiYuQexPX5URVzC670D9+HeKwSa58t7q2iNHBAuJGP1kx0
         B+4u2wQ0a62zZng0v0RAxtqumHT27GdThts0PLLVPO7r4FqeC1Zozr+B+YzwAL1xV3WW
         /N/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=Akj1qwM5IWxi7OugIJR4G/7qT/LOkV7Tlq/xgqHmzbg=;
        b=i5p2khZoVT1cLFAYKeEdWt4JUxaWEiypx1tgfw7iVWzspnZspaB1QygZzePONwO4hY
         y+7raNHteMrNfFf7GAUQmiqRsJ5iiSEN/S8nObwlGIft1CcfRwUowAvIzUxw6NfZN+Sk
         xjtN7J8jFII1/HtsZyIvjjn0JjLtAJlaFfV0iDPVFg0sg/jtuJpIYHGP4TIsBmBanu/u
         AURPuQmw083IlG3b8eWCJ0LUc2uRVKVM2pW1dDWkXeXJ5GKEKYWi2IokfYypaYmO2GqN
         NVLZFUtLxNdjryyhYe4I+CamaOlZtQWjXQ+p0hpn+b7N2Fg7TG0t9JV7x4FveknxzU/P
         mCIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id c3si217132pls.0.2021.03.23.08.04.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 23 Mar 2021 08:04:15 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) client-ip=202.181.97.72;
Received: from fsav104.sakura.ne.jp (fsav104.sakura.ne.jp [27.133.134.231])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 12NF49vn052069;
	Wed, 24 Mar 2021 00:04:09 +0900 (JST)
	(envelope-from penguin-kernel@i-love.sakura.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav104.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav104.sakura.ne.jp);
 Wed, 24 Mar 2021 00:04:09 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav104.sakura.ne.jp)
Received: from [192.168.1.9] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 12NF48RW052065
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Wed, 24 Mar 2021 00:04:09 +0900 (JST)
	(envelope-from penguin-kernel@i-love.sakura.ne.jp)
Subject: Re: [5.12-rc4] int3 problem at kfence_alloc() when allocating memory.
To: Marco Elver <elver@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>,
        Alexander Potapenko <glider@google.com>,
        Dmitry Vyukov <dvyukov@google.com>
References: <ebe1d0bd-39fe-d7a0-9dcc-d8e70895a078@i-love.sakura.ne.jp>
 <CANpmjNM60W4nYEYCEt9SJ9f4L194WEk_ORey8s+DbgnokJZ53g@mail.gmail.com>
 <YFnmayHmYcrNk3V+@elver.google.com>
 <CANpmjNM5xCWXdErqv4btAL2yvqVpWWXcjG6659hNy_NBQ0YdaA@mail.gmail.com>
From: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Message-ID: <7e26707c-0f08-7c1d-250e-a9004e804085@i-love.sakura.ne.jp>
Date: Wed, 24 Mar 2021 00:04:07 +0900
User-Agent: Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.8.1
MIME-Version: 1.0
In-Reply-To: <CANpmjNM5xCWXdErqv4btAL2yvqVpWWXcjG6659hNy_NBQ0YdaA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of penguin-kernel@i-love.sakura.ne.jp
 designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

On 2021/03/23 23:46, Marco Elver wrote:
> I reported https://bugs.launchpad.net/qemu/+bug/1920934 -- probably
> not much else we can do for now.

I see. Thank you for debugging.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7e26707c-0f08-7c1d-250e-a9004e804085%40i-love.sakura.ne.jp.
