Return-Path: <kasan-dev+bncBCAP7WGUVIKBB4M33OOQMGQET7NYWMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 757B265ECAE
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Jan 2023 14:17:39 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id gd5-20020a17090b0fc500b00225d56a7b06sf10964757pjb.3
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Jan 2023 05:17:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672924657; cv=pass;
        d=google.com; s=arc-20160816;
        b=jkINW1QZYgWM/yHGhbVLk/+VsuBIpzLuBcFqldLke/nd+9XNQ+Fzf0z9CzDCf7i82p
         68Bo4ODPEoF63SjYx9fsg9L1+BqhwJHFMoo1pLeR8BW5KsTctSBtncH3q81tn2tIYZPI
         iKShyfn0USCGQLKZb5cpI09M/usoVAKrsIqh3w35cGzsSO8aoxyMOaWqE1+z2IeJh0p+
         ZH8Ak85y1tKCm5Ga9f5bA+aMzwUxbkRaQdqxUV/rBA1qH26Jd7JA2dorSi/gN+rUVDPn
         CZGeGuQTvFcf9BZ+P2jMN0d8CBRJuzqY+u8OqZfMLz3bsVKp2jTOH7IregVXSz9HS2MQ
         Z6kA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=APIiL3UMzMev+OUv2dxMqKWvgsn76qnqzuE9Ggbm1Ok=;
        b=XOHRpZU6WyGa7HLmaU14achMDESg/ZqTfrn206wZ4LCoFBtM9s+/Bt72dpkgcqAU2y
         djx/7PUzGu76ehersNhzEDnqS3S8hne4g68lzAJVPL04iX7Yn85vYmt94FbcBnOxISjC
         kRrheRUiW7Zn969CIYapOgCe37bhugzhcW2mUEVw+V6+UxcOW1zp31kCT//WRSTAqDcz
         I9CY/W9YVDA+90ihwl5JeuuQXQ6JRA749LzUFjPX+9eS56UONs6UaK/S65Kjxwbeis7U
         4ui/vX+3snihFbk9ZLfCuxtv8AFNQ/+w+1+WiD6EqXHbFjwndpYi58FhYWRTXTzmkiVS
         wtFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:to:content-language
         :subject:user-agent:mime-version:date:message-id:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=APIiL3UMzMev+OUv2dxMqKWvgsn76qnqzuE9Ggbm1Ok=;
        b=gtrfWF/Q/LzyJF7Pb9GMOOrl/GUX1iOE3JtANS+Wk6mn4NPEt2wJ8N6h6pweAKC8Sv
         sF+kMc4ZEn7XT/qO5IY8oDTwBjXXz7iBa0BEMorMdTWgkgproYOhTMyfr1YU4dMIFNCI
         cuAh1aOjX4tLly1Dxtk49WkEsUSmGgyLA7V+R55ivLujhTtAHJm5RQN7IsIhq8vgeOR3
         o3oITkFh1NSGFVhRBWHfztSzjsHb9PpeQtMJbzjyuiO2XADO9BmmVPt9rAIBbzoKJqTJ
         Fct/z4VE+d4P6ArrVE6DBneUhpR12OE63mwyEPGPpRV4aSxEc9kWj484OnPZwBeAnax/
         jLrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:to:content-language:subject:user-agent:mime-version
         :date:message-id:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=APIiL3UMzMev+OUv2dxMqKWvgsn76qnqzuE9Ggbm1Ok=;
        b=ZxTqyVz2WxD9afLLA1aDD77sKfTDMGuLiAd/q9rFuGVJdAeCIUh/Pvbr3u9pe5/vCV
         cX1rOmGJtLMNCzfhNWWx1p+zf1bXk8YUdjIHLu4kz3o+t7Yz/Zt09k0uCPqTH8AIm2np
         0TqqPe7SXGZbswmCrvRkHVds5uXdwB5pYFSroqHoPhZW/mRjegyLFlwVGaRsvD5Z7H3b
         QsX9wdhg+FRFGnVVe6tEXu+ofOCf4ke3Obwiei9rdmUX/f/D1StVeI1CrvQtbKcj0rEW
         UG6xFFWek0XHqIIPCbmO7/wRHOokDdbhl+kv/IUN0EwBqU0lfCqwlDht4DvL4ufyovvM
         rq7A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2komd79g5xCtaKOA3hsJSdbwILSRIweezf3b6soLL46SWaeQHAiN
	jCr1pqWMRYjgjlcK27jKs3I=
X-Google-Smtp-Source: AMrXdXveiD77eY7rM1qTdvXhihkOA5X/pfsbW2BFsT8DDfafwSvEvVxMOFxssjwQGOfkMbmCvoekdg==
X-Received: by 2002:a65:628d:0:b0:483:f9ad:35dd with SMTP id f13-20020a65628d000000b00483f9ad35ddmr3432233pgv.121.1672924657521;
        Thu, 05 Jan 2023 05:17:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:a015:b0:210:6f33:e22d with SMTP id
 q21-20020a17090aa01500b002106f33e22dls39991059pjp.2.-pod-control-gmail; Thu,
 05 Jan 2023 05:17:36 -0800 (PST)
X-Received: by 2002:a17:903:3284:b0:188:82fc:e277 with SMTP id jh4-20020a170903328400b0018882fce277mr59868716plb.12.1672924656646;
        Thu, 05 Jan 2023 05:17:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672924656; cv=none;
        d=google.com; s=arc-20160816;
        b=crNmQpUZS08b4hOM2nYhgNCjI2zyo/C5m7o6zp4q+rAQN17/7KGwxQmF9KK64ER6eV
         RtrGmcS2c2jSOkkL9fd5EelIK14zKauXARaharSAxZRSug0240nN9W2LxGE8VciELJ1d
         Y/YDmP2BiViq5xBR7bAFV3fpRUnj3ZJRiWqUyo8e/VXvrG4DqZR4igLrCA/i++PefHOn
         awDKklU3l4mnlMMpBg4ngHeM8UkSNM6vLJkd7XoHdirdCw0yK503oXcGRNwFp9z24e/b
         DMrdtiQ7FX11/OJfog9wjfW/7GtaoOX/zFMgXYr1o/4uJjTKoyw7ijSKg0n+F3d8toRO
         oS9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=VIbQI53cWjz9kyM9t24jRkeRoQ0B76yI/QbCLokfVcY=;
        b=YXsBOQHgiccr+F2Nux4JUE/hu+/ic3nxDUfupOO5EbbVDNCzL//5JRaW97nO+T2Mze
         8p94p27C2tPn8eQIzZ1CEWKRTSo4AVnpbqoWZEHyh1wfiHT4wxCmgsybNT3HywawrNyh
         kWBGDGYVlQVM8ACe3+HeNnpDfrH5DJO/FunN9mKhfgfYL7c7mTE7tSO4dSUHtJ4+shuE
         +7v9vJBkZn2DhF7CeXggCUa0kt48RsneXZ78DIIEiA+VrftWT+HciVPVY4n44USiaPmp
         yd7oXgpUxUoj+IQ0v/aeMt3SBbFr/tHD67JN9wlnL5ikYgd0RWfTfCyuc44g0UswW/cR
         KmuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id t9-20020a170902e84900b00178112d1196si2415133plg.4.2023.01.05.05.17.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 05 Jan 2023 05:17:36 -0800 (PST)
Received-SPF: none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) client-ip=202.181.97.72;
Received: from fsav313.sakura.ne.jp (fsav313.sakura.ne.jp [153.120.85.144])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 305DHOub054514;
	Thu, 5 Jan 2023 22:17:24 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav313.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav313.sakura.ne.jp);
 Thu, 05 Jan 2023 22:17:24 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav313.sakura.ne.jp)
Received: from [192.168.1.20] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 305DHOkc054511
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Thu, 5 Jan 2023 22:17:24 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <032386fc-fffb-1f17-8cfd-94b35b6947ee@I-love.SAKURA.ne.jp>
Date: Thu, 5 Jan 2023 22:17:24 +0900
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.1
Subject: Re: [PATCH] fbcon: Use kzalloc() in fbcon_prepare_logo()
Content-Language: en-US
To: Alexander Potapenko <glider@google.com>,
        Geert Uytterhoeven <geert@linux-m68k.org>,
        Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
        kasan-dev <kasan-dev@googlegroups.com>, Helge Deller <deller@gmx.de>,
        Linux Fbdev development list <linux-fbdev@vger.kernel.org>,
        DRI <dri-devel@lists.freedesktop.org>,
        Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
        Kees Cook <keescook@chromium.org>
References: <cad03d25-0ea0-32c4-8173-fd1895314bce@I-love.SAKURA.ne.jp>
 <CAMuHMdUH4CU9EfoirSxjivg08FDimtstn7hizemzyQzYeq6b6g@mail.gmail.com>
 <86bdfea2-7125-2e54-c2c0-920f28ff80ce@I-love.SAKURA.ne.jp>
 <CAG_fn=VJrJDNSea6DksLt5uBe_sDu0+8Ofg+ifscOyDdMKj3XQ@mail.gmail.com>
 <Y7a6XkCNTkxxGMNC@phenom.ffwll.local>
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
In-Reply-To: <Y7a6XkCNTkxxGMNC@phenom.ffwll.local>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=none
 (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

On 2023/01/05 20:54, Daniel Vetter wrote:
>>> . Plain memset() in arch/x86/include/asm/string_64.h is redirected to __msan_memset()
>>> but memsetXX() are not redirected to __msan_memsetXX(). That is, memory initialization
>>> via memsetXX() results in KMSAN's shadow memory being not updated.
>>>
>>> KMSAN folks, how should we fix this problem?
>>> Redirect assembly-implemented memset16(size) to memset(size*2) if KMSAN is enabled?
>>>
>>
>> I think the easiest way to fix it would be disable memsetXX asm
>> implementations by something like:
>>
>> -------------------------------------------------------------------------------------------------
>> diff --git a/arch/x86/include/asm/string_64.h b/arch/x86/include/asm/string_64.h
>> index 888731ccf1f67..5fb330150a7d1 100644
>> --- a/arch/x86/include/asm/string_64.h
>> +++ b/arch/x86/include/asm/string_64.h
>> @@ -33,6 +33,7 @@ void *memset(void *s, int c, size_t n);
>>  #endif
>>  void *__memset(void *s, int c, size_t n);
>>
>> +#if !defined(__SANITIZE_MEMORY__)
>>  #define __HAVE_ARCH_MEMSET16
>>  static inline void *memset16(uint16_t *s, uint16_t v, size_t n)
>>  {
>> @@ -68,6 +69,7 @@ static inline void *memset64(uint64_t *s, uint64_t
>> v, size_t n)
>>                      : "memory");
>>         return s;
>>  }
>> +#endif
> 
> So ... what should I do here? Can someone please send me a revert or patch
> to apply. I don't think I should do this, since I already tossed my credit
> for not looking at stuff carefully enough into the wind :-)
> -Daniel
> 
>>
>>  #define __HAVE_ARCH_MEMMOVE
>>  #if defined(__SANITIZE_MEMORY__) && defined(__NO_FORTIFY)
>> -------------------------------------------------------------------------------------------------
>>
>> This way we'll just pick the existing C implementations instead of
>> reinventing them.
>>

I'd like to avoid touching per-arch asm/string.h files if possible.

Can't we do like below (i.e. keep asm implementations as-is, but
automatically redirect to __msan_memset()) ? If yes, we could move all
__msan_*() redirection from per-arch asm/string.h files to the common
linux/string.h file?

diff --git a/include/linux/string.h b/include/linux/string.h
index c062c581a98b..403813b04e00 100644
--- a/include/linux/string.h
+++ b/include/linux/string.h
@@ -360,4 +360,15 @@ static __always_inline size_t str_has_prefix(const char *str, const char *prefix
 	return strncmp(str, prefix, len) == 0 ? len : 0;
 }
 
+#if defined(__SANITIZE_MEMORY__) && defined(__NO_FORTIFY)
+#undef memset
+#define memset(dest, src, count) __msan_memset((dest), (src), (count))
+#undef memset16
+#define memset16(dest, src, count) __msan_memset((dest), (src), (count) << 1)
+#undef memset32
+#define memset32(dest, src, count) __msan_memset((dest), (src), (count) << 2)
+#undef memset64
+#define memset64(dest, src, count) __msan_memset((dest), (src), (count) << 3)
+#endif
+
 #endif /* _LINUX_STRING_H_ */


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/032386fc-fffb-1f17-8cfd-94b35b6947ee%40I-love.SAKURA.ne.jp.
