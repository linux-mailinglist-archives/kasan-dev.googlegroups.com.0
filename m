Return-Path: <kasan-dev+bncBC4KTZOM34PBBRH3RO2QMGQER2LQDOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id A665393CC79
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Jul 2024 03:37:09 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-5a69c1f5691sf3788738a12.1
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2024 18:37:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721957829; cv=pass;
        d=google.com; s=arc-20160816;
        b=v107uS9eZiNUEjn2NK211liAvNT2+kNn8qG7kL6ts+hUV8PgpQrZvZvTof9iamUeYD
         5zdaiRN+uvuTlal1mJ5m5mz3FYaWhPjxwK/8WsfqAM4mV9TGq9WaM2oJJqrX0/4KOb+I
         buo1y4Xt02mJDSgK1dP1wV6nNCQFG5h38rqgnxiDsFZhCaKbSs/ZKcu5ygbVOy3Qfd8V
         C85O5la4UrrGtkHJl7z0jQT9GhG59yyqWTTlAenMXta5Bvx3o/Ow6mQu+qTdAYhQa9D7
         Ve9B+g38qaSoTEwLnP9ojhOV6UjLHbRbHjR3AkPJ/BZ/qBpYDWRymCOSKRHgA3MgFbxi
         I5ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=0dkv05WROQK6lwLVRj4sm/lHlwIAlMP7yCjYNwYu4Gg=;
        fh=Hd6JB2GavEvl6lXv/hGnav/oZfl6wf2M3qsbeLc4kc4=;
        b=xrrw+vqpx62ectIPZEz03Yve5JE0KT4EDzjyknWgJmHD440s3t9Qw6GHZ/4CXhYWTj
         2WYpNjy+dsMnwPqQktQNF3nRBLRTno7SUVedWn47WfjtR/gKUf6qKFLNNF7NHwZNoHiQ
         bayiq0nkE8+6HJrij0hiKWKRnOlB+8+IroY2cFQT4jMSfKr/8SaJwrXJk57nGI4BGXso
         N+bXlRom1gCxnGoQyT7lsGZMm9BPfRgb/BlfYH8oSxMlfLXbwmDo0SHhjs9mu+Uypmw5
         n+r2cyaSGWrzA4mRgqyNUMCFOHJjx8IQb2ojtIuP78wul9QaXKReYHToRyjXQfh0M2ez
         P7iA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dzm91@hust.edu.cn designates 206.189.21.223 as permitted sender) smtp.mailfrom=dzm91@hust.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721957829; x=1722562629; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=0dkv05WROQK6lwLVRj4sm/lHlwIAlMP7yCjYNwYu4Gg=;
        b=iUyCw23DRiZmbJYLvTf5RV9jfCfxqhJHJVKJMjKRifQhWJmNbF19riGD502D8fNDJQ
         +d9BbdxQKIIpHUWYftksl+/ZhiVO7YctrL2qeKTKPCKRtbRusn7QwCGmA+4VaErkZv4i
         mig38EZIRFH9I2atfy17yZ9IPHVX5LH0GBKjx177+7exD8rtyibpsJdFx4KkUSZdbaeS
         YKUfO/tt9EbCaOUZdz/vjjLUWbXOZut+UHkH11CBt6jXEYfQkqNs934DGGIxSmiCoPXN
         +5kLdXrq4HV68ElcPfxX04VcwQHfcvsqgyPTjxJcX8fF726vWCW945J4FOpCUnMUBtDA
         Lq1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721957829; x=1722562629;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=0dkv05WROQK6lwLVRj4sm/lHlwIAlMP7yCjYNwYu4Gg=;
        b=AnNTDng/KFx/AAv5PuYUVI3J7h80poI+0wmM8vglnSLWFtMGsuQSR03vjZV9W0YDvT
         5VhNAxzV5zv/zmmR15W4B8dEnJbUoohlcIdmdhziiK82VYMkwyChsWEcmTFk/lMiCZoZ
         t1GrXna30GfXF6UhmYqSoxSv1uqoioEMmO7n1KiHpAImJva+exocRLxuDNPAWV6x0dkV
         o5oGzSPDe7tjTAwj4pvpQWUORAf98axfqYVMdZqn2JXIrfrUKIStIe37wnENTh58XCoF
         6EW6cFVTfTFgMMrBXhbvaN06flwyd/dXzsJe2Li9kjTSICMRbKbqRrZEszSs+u892bBp
         TdUg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUOeU+HZfpudHHiGmjGgQHSbYUMOpOxQDZPxvjkb/LpP1ogBpkCTvObztbsBQZx0eYDTE6rjq/HnBeMW5psJK7GwhhcXAQl0Q==
X-Gm-Message-State: AOJu0YzgcARqsFLL47r/jafX/7N7SYjWM3sxbz/uqG7J7SHAeGui/mQL
	c8HZal/03iOajMMJc9zsE0KGLlExh4NECTkBWRxDxJKeJoZL2wJk
X-Google-Smtp-Source: AGHT+IH5cUJhcJowLm8C7u4pKLpGFl9p+jOHvULZZmc1cHURldXIGBi8sfjh9vuyoFXT09phlm+oNg==
X-Received: by 2002:a05:6402:42c4:b0:5a1:5c0c:cbd6 with SMTP id 4fb4d7f45d1cf-5ac12f6fc9amr5198879a12.8.1721957828703;
        Thu, 25 Jul 2024 18:37:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:4029:b0:583:9e8e:cd8c with SMTP id
 4fb4d7f45d1cf-5ac0d0ec1e5ls841762a12.1.-pod-prod-00-eu; Thu, 25 Jul 2024
 18:37:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXL3pd1o1iCwgUkMASrMCxkpU1t9oBf/MJ8oYb31xSkWwxUd2W6OuzeqOeZiGDiQjnaiShZyqUkLj3fviLDCT8ojleJdXqkiQMwJg==
X-Received: by 2002:a50:cc9d:0:b0:58b:bb69:763e with SMTP id 4fb4d7f45d1cf-5ac1299a5a7mr4150796a12.7.1721957826923;
        Thu, 25 Jul 2024 18:37:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721957826; cv=none;
        d=google.com; s=arc-20160816;
        b=BbGdQ0EzPn2Wyp/G6v/v7XoC1CoqrcrSBqUEWl2z/ya5Ny/eZFn+SLIah/T3xAv0Qp
         jlIIccf7NR+ko0iUWF4ZNT162jiRiITCRRzWOaChMRwAyw7kL0sl67BmarpNM+iuqx/P
         P0rUywnsqcrv2EdHInRAs5ChxpKK0MFKsEBAz59x5yCyCUdQmD8duIci92U/20YW2H6k
         GQ0RCKslIbkL2UAzWBdv0lMf6SUo43pAgcLYfwS+YThsE58wSRUo7mI2fBiDagOxz45r
         DcjqgZXAq4BT2v+kA1cIxDMCPgXUSjwwooVs5IgK2+cFWRdE8ii9IZWClOqnD69hyQmf
         1ijg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id;
        bh=A+L9ndye4ie2ZETKCBp+nNOK5U+MpB35+IY9Qap4umE=;
        fh=Nlsmzx6/yVKlJKHr5/6wQ9IlZy7qikBvuFt0VG6SCTo=;
        b=dRRe/1GKcNt3EURyX8B+yEMrS75/AIJgXZ9ww14WlAVLwCLDAUF7iaaFECyU6Mt5V6
         HbSin1SKcu7OzQEYlfIkO933Tzt0tLRVNuH0j6b65MHbJJvXhQK0k4eWUbNLdnDLrTjL
         SnWGFxCibzmp8alsH8mGK7lLHAT5IBkHi5jcdqi/DSUi7UgFsUKnN7UZKGoVVDg0U18z
         wEshQKCMBJO4hwy7kKabJMngqyKPnxwboNLcDPKyhmHPWFrsLBo9cYycLMkN510Cma6v
         +EYUZjgqI5dtuwSlyTNIv/MXJDGekIYko5hVB6+oGODGyDrRNyUWPSp8vFNvxvAbtABQ
         CDIg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dzm91@hust.edu.cn designates 206.189.21.223 as permitted sender) smtp.mailfrom=dzm91@hust.edu.cn
Received: from zg8tmja2lje4os4yms4ymjma.icoremail.net (zg8tmja2lje4os4yms4ymjma.icoremail.net. [206.189.21.223])
        by gmr-mx.google.com with ESMTP id 4fb4d7f45d1cf-5ac60cf50bbsi69156a12.0.2024.07.25.18.37.06;
        Thu, 25 Jul 2024 18:37:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of dzm91@hust.edu.cn designates 206.189.21.223 as permitted sender) client-ip=206.189.21.223;
Received: from hust.edu.cn (unknown [172.16.0.50])
	by app1 (Coremail) with SMTP id HgEQrACHj2+Z_aJmdPX7AQ--.17556S2;
	Fri, 26 Jul 2024 09:36:25 +0800 (CST)
Received: from [10.12.168.59] (unknown [10.12.168.59])
	by gateway (Coremail) with SMTP id _____wAnJ3mW_aJmNApyAA--.5651S2;
	Fri, 26 Jul 2024 09:36:24 +0800 (CST)
Message-ID: <a6285062-4e36-431e-b902-48f4bee620e0@hust.edu.cn>
Date: Fri, 26 Jul 2024 09:36:22 +0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] docs: update dev-tools/kcsan.rst url about KTSAN
To: Haoyang Liu <tttturtleruss@hust.edu.cn>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Jonathan Corbet <corbet@lwn.net>
Cc: hust-os-kernel-patches@googlegroups.com, kasan-dev@googlegroups.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org
References: <20240725174632.23803-1-tttturtleruss@hust.edu.cn>
From: Dongliang Mu <dzm91@hust.edu.cn>
In-Reply-To: <20240725174632.23803-1-tttturtleruss@hust.edu.cn>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-CM-TRANSID: HgEQrACHj2+Z_aJmdPX7AQ--.17556S2
X-Coremail-Antispam: 1UD129KBjvJXoW7Zr4rJF4DJr1DZF1kGF13twb_yoW8GrWxpa
	yfuFyI9rn0gr17K3yjgw40krW8AFZ7Xr4UG3W8Ja1FqrsI9F9IqrWagw1rXFyUZFWrAFW2
	vF48Za4Fv3WDAaUanT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUB0b7Iv0xC_Cr1lb4IE77IF4wAFc2x0x2IEx4CE42xK8VAvwI8I
	cIk0rVWrJVCq3wA2ocxC64kIII0Yj41l84x0c7CEw4AK67xGY2AK021l84ACjcxK6xIIjx
	v20xvE14v26w1j6s0DM28EF7xvwVC0I7IYx2IY6xkF7I0E14v26F4j6r4UJwA2z4x0Y4vE
	x4A2jsIE14v26rxl6s0DM28EF7xvwVC2z280aVCY1x0267AKxVW0oVCq3wAac4AC62xK8x
	CEY4vEwIxC4wAS0I0E0xvYzxvE52x082IY62kv0487Mc804VCY07AIYIkI8VC2zVCFFI0U
	Mc02F40EFcxC0VAKzVAqx4xG6I80ewAv7VACjcxG62k0Y48FwI0_Gr1j6F4UJwAv7VCjz4
	8v1sIEY20_GFW3Jr1UJwAv7VCY1x0262k0Y48FwI0_Gr1j6F4UJwAm72CE4IkC6x0Yz7v_
	Jr0_Gr1lF7xvr2IY64vIr41l42xK82IYc2Ij64vIr41l42xK82IY6x8ErcxFaVAv8VW8uF
	yUJr1UMxC20s026xCaFVCjc4AY6r1j6r4UMI8I3I0E5I8CrVAFwI0_Jr0_Jr4lx2IqxVCj
	r7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVWUtVW8ZwCIc40Y0x0EwIxGrwCI42IY6x
	IIjxv20xvE14v26r1j6r1xMIIF0xvE2Ix0cI8IcVCY1x0267AKxVWUJVW8JwCI42IY6xAI
	w20EY4v20xvaj40_Jr0_JF4lIxAIcVC2z280aVAFwI0_Jr0_Gr1lIxAIcVC2z280aVCY1x
	0267AKxVWUJVW8JbIYCTnIWIevJa73UjIFyTuYvjxUsrWFUUUUU
X-CM-SenderInfo: asqsiiirqrkko6kx23oohg3hdfq/
X-Original-Sender: dzm91@hust.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of dzm91@hust.edu.cn designates 206.189.21.223 as
 permitted sender) smtp.mailfrom=dzm91@hust.edu.cn
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


On 2024/7/26 01:46, Haoyang Liu wrote:
> The KTSAN doc has moved to
> https://github.com/google/kernel-sanitizers/blob/master/KTSAN.md.
> Update the url in kcsan.rst accordingly.
>
> Signed-off-by: Haoyang Liu <tttturtleruss@hust.edu.cn>

Although the old link is still accessible, I agree to use the newer one.

If this patch is merged, you need to change your Chinese version to 
catch up.

Reviewed-by: Dongliang Mu <dzm91@hust.edu.cn>

> ---
>   Documentation/dev-tools/kcsan.rst | 3 ++-
>   1 file changed, 2 insertions(+), 1 deletion(-)
>
> diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
> index 02143f060b22..d81c42d1063e 100644
> --- a/Documentation/dev-tools/kcsan.rst
> +++ b/Documentation/dev-tools/kcsan.rst
> @@ -361,7 +361,8 @@ Alternatives Considered
>   -----------------------
>   
>   An alternative data race detection approach for the kernel can be found in the
> -`Kernel Thread Sanitizer (KTSAN) <https://github.com/google/ktsan/wiki>`_.
> +`Kernel Thread Sanitizer (KTSAN)
> +<https://github.com/google/kernel-sanitizers/blob/master/KTSAN.md>`_.
>   KTSAN is a happens-before data race detector, which explicitly establishes the
>   happens-before order between memory operations, which can then be used to
>   determine data races as defined in `Data Races`_.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a6285062-4e36-431e-b902-48f4bee620e0%40hust.edu.cn.
