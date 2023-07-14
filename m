Return-Path: <kasan-dev+bncBDGZTDNQ3ICBBSMFYWSQMGQEQIY7QTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 10675753B3C
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Jul 2023 14:42:52 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id 46e09a7af769-6b74e9192a1sf2901008a34.0
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Jul 2023 05:42:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689338570; cv=pass;
        d=google.com; s=arc-20160816;
        b=fgU2Q2Ly/OkxgGs59oJCBHitMu9omI8e0epeXcjB+R5yt0ZBlYyqcOTjBsHjCaq81R
         OtfUfkVtnoDPmJ8+gHXUbq/qa79CntgKGGOqRTskPsAmLqpN59Jbl8y9T9Scs8HDnLZT
         u/BZl5xFyuzYIDPydxcK+9TrAlN1NmRWhQpHxv5q18wPqG/jeYThP9XABB0kqaIRDo3k
         oneeuqbB5VQmLHsIIZBA7t2f3NjmNfQ/Eh7Bocc4aaAqf6VmqtM7cf3RHJQgXXHCQ+3s
         OdYaOJyfvGXpPFfQY0w81Xnb2iGFzyWHzxG8L7ITCwsIqzzKa2QZ+5zVfNVFJuMMM5Mv
         hKoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=4Zb6yEWpIKMDS09EPNiSJsYPoGLqeZJXB2eQSxCKdwE=;
        fh=nyRfnF3ZBA5LUMd/t/UqcaY8vveQyyiaxojj7j19nYE=;
        b=kXWYphIqsRRxc52QqKuaRfb7rs5D09t5CBhsOZ+4rG9xFshlZuiBoxP34RNY+VkY0M
         DWvMQ3Hy1YqSNBNus20ayJ+/Zk8xxaf7EX7ceu1v32OwJQqn3tdaPt7evZLYt4c+ehwE
         N7frqcwD5xCumJ/aCM/G5B/tQfRiXkMqHFGkhNnwbBuJdndmgE93VPf11jFrCEdoPrG1
         hyTBtOZn6ao7J3A8WhfhOKsSmQb0hu+wQQ0Ldcdrt8l5GAK+8HAysVOH4GmP7d29YWoc
         5Yh7gVcFsCQiTfh6cU6lRMvSQlb9dqxV3BuzzCjK1NFafFb7ihFZWMYmT9EB7rE25qpb
         uiRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=NgFvlWvT;
       spf=pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689338570; x=1691930570;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=4Zb6yEWpIKMDS09EPNiSJsYPoGLqeZJXB2eQSxCKdwE=;
        b=ToEPR88ywRs+GzjtV12yG8Rj7DZIaGiPIagsK3wbArO6LcLFuX9rg3YMBhNmLM3GZk
         amhLlDAq+BSeFtEelP6zlDbDko0BOMYJXN7Gll/5pvVLKy2ic6l0nOrGzwZQPP0j0+hD
         T+kmw205TuqtuE1OGWm45AC7ULCBCBzuQSyQ160/hGbxDTHHHOgyTWhTS1ncj2eL1wNu
         adRiX0IKLP/Ow6eCaLkKusGvzypmxsQDw0/bP6eQDlNJqGo9R7CDmZRg2R+LF/SjLvWZ
         9PPigBFADI+a3b0NHoH2y3NYtVVluKjyCd5VYDaQVaxEda86hLdpDqezO6NG9EPXRb04
         JZwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689338570; x=1691930570;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4Zb6yEWpIKMDS09EPNiSJsYPoGLqeZJXB2eQSxCKdwE=;
        b=lw8HAaW3XoalI/+4DoeGMn6dt+HqxahBvmpADwpcXfZsrClpAGnxPy1HTGas89V1Dm
         ZrRJ9+3WdLUfBce4xvbN73DEWNAnddszF8Z3jwq+L/vjJKazbwAib54NJsTWPv/F7o+z
         D9lYwj1nIMAfte7MZHjXjDOMEeSum4hJjM6uqCzKdIfSU0ZmP9VyREJkntDSt8OewU2o
         aF53ElqVr4Tr4ka5UreR5DsHjk6wE09/6DQCHU5PIaDSAo/zqELMZDWY3/YNxl1qdkqM
         FuRHRX2sLQcWKKM4ordm0euRgCm7ysYwwFI9CW/PAZ3GYu1YbJNtDudvuMkAoSo070RG
         GSLg==
X-Gm-Message-State: ABy/qLZyJ/O4Zt31iMWIoot6yBOVTgKl9CiKSy54XYM9tE38AyE69hCp
	Oc9gvglhbaAtzZTTGoelSuc=
X-Google-Smtp-Source: APBJJlGfS+HUSkCFYrRw3s3o6WDIakCVPdJFjnyeL4A0/1VkIlFxej+4SBMcWu5iHUvZt0OR29AxJw==
X-Received: by 2002:a05:6358:9913:b0:135:96fa:bff3 with SMTP id w19-20020a056358991300b0013596fabff3mr5202797rwa.4.1689338570130;
        Fri, 14 Jul 2023 05:42:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:18ca:b0:c5e:d901:7577 with SMTP id
 ck10-20020a05690218ca00b00c5ed9017577ls1236262ybb.1.-pod-prod-01-us; Fri, 14
 Jul 2023 05:42:49 -0700 (PDT)
X-Received: by 2002:a0d:d706:0:b0:57a:69eb:7a06 with SMTP id z6-20020a0dd706000000b0057a69eb7a06mr3972020ywd.25.1689338569513;
        Fri, 14 Jul 2023 05:42:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689338569; cv=none;
        d=google.com; s=arc-20160816;
        b=Wjh+r/ADUgz3J3VFs5c7WDIXyaZ/qHglrDUj0rLUt2ETmFpHEs9+1Zo0Vqlq1lGEQ9
         jryLQrgs7gaX7gbmFrGxygPqTKx+H0i67OmFHBiG3uZ9Cye9Hn/Ly0L4QO++x+JxaivR
         Ji2rGClUnAygpt26kZ3QGGX0msmW71O+G8RQ2K0w4dCOuBpbK+qkI9QMUqwFZ7YHGdP+
         W5SKgB8kZ5SluRmQdkV0iTaPhEYXvGnFabQRAoXMFc+amfEH7QCSbiExsfXv8zMxI92/
         nNR52bgirtRbAV4l80gjj84rOCb7yvPck6308cS+iDFGE1Pl8efcjJISRNh2lhuIIxUi
         YYZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=pF1G5UAt4ngbjaLsrBFjCg7Dq+2zgqRM/LN9T1v8nyg=;
        fh=O/E+pwhusGEqj15k//SbaGwQizR6eMDVGTQI/Ohznag=;
        b=wuL/hpPyPWofLurNxYyDaKmEHB8Eczxnr18iw2KJWnUf5lg7XKxN9bBR+GfckW6NYD
         i795Yj8dUoXbqbmqaYuV/gQdgGlP0FVcR3oMPE/0EBn4H3fB41DQhr+R70vdR5ocPDmX
         /iDNRKi9KrJUiz4UwMfY5enMKwLzG4yN97xEevWnn86wAgckPQBU5yr0pGlnN8LG/lLb
         SMqEfZesjaWuClabT/lJ06waRXWXBSecqipsoP2/RW+hgwRz42fOyrEaTH8o3cPqUFhi
         c6n6XHRLoBQYmOxiN6RsqKna71uI76VuHlKP1P3o93fEwo/DNUrvtXg9vIACl/jmMpzS
         cPAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=NgFvlWvT;
       spf=pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-pl1-x629.google.com (mail-pl1-x629.google.com. [2607:f8b0:4864:20::629])
        by gmr-mx.google.com with ESMTPS id df6-20020a05690c0f8600b0056190301fb2si308740ywb.1.2023.07.14.05.42.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Jul 2023 05:42:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::629 as permitted sender) client-ip=2607:f8b0:4864:20::629;
Received: by mail-pl1-x629.google.com with SMTP id d9443c01a7336-1b89e10d356so11470045ad.3
        for <kasan-dev@googlegroups.com>; Fri, 14 Jul 2023 05:42:49 -0700 (PDT)
X-Received: by 2002:a17:902:8689:b0:1bb:1a64:5a74 with SMTP id g9-20020a170902868900b001bb1a645a74mr598470plo.33.1689338568711;
        Fri, 14 Jul 2023 05:42:48 -0700 (PDT)
Received: from [10.254.16.139] ([139.177.225.225])
        by smtp.gmail.com with ESMTPSA id b14-20020a170903228e00b001b890b3bbb1sm7667622plh.211.2023.07.14.05.42.44
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Jul 2023 05:42:48 -0700 (PDT)
Message-ID: <710342c1-eccd-d2ad-9206-f8770ad30ace@bytedance.com>
Date: Fri, 14 Jul 2023 20:42:42 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:102.0)
 Gecko/20100101 Thunderbird/102.13.0
Subject: Re: [PATCH v2] mm: kfence: allocate kfence_metadata at runtime
To: glider@google.com, elver@google.com, dvyukov@google.com,
 akpm@linux-foundation.org
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, muchun.song@linux.dev,
 Peng Zhang <zhangpeng.00@bytedance.com>
References: <20230712081616.45177-1-zhangpeng.00@bytedance.com>
From: "'Peng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20230712081616.45177-1-zhangpeng.00@bytedance.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: zhangpeng.00@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b=NgFvlWvT;       spf=pass
 (google.com: domain of zhangpeng.00@bytedance.com designates
 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
X-Original-From: Peng Zhang <zhangpeng.00@bytedance.com>
Reply-To: Peng Zhang <zhangpeng.00@bytedance.com>
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

Hi all,

Are there any other comments here?
Welcome any comments.

Thanks,
Peng

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/710342c1-eccd-d2ad-9206-f8770ad30ace%40bytedance.com.
