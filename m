Return-Path: <kasan-dev+bncBCCMH5WKTMGRBBUDRCQAMGQEXQIAU3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe38.google.com (mail-vs1-xe38.google.com [IPv6:2607:f8b0:4864:20::e38])
	by mail.lfdr.de (Postfix) with ESMTPS id 670C26A9943
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Mar 2023 15:17:43 +0100 (CET)
Received: by mail-vs1-xe38.google.com with SMTP id b10-20020a67b34a000000b0041f71775311sf942822vsm.23
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Mar 2023 06:17:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677853062; cv=pass;
        d=google.com; s=arc-20160816;
        b=ywEnVtNO69eEuYI73mMvxi68EPWMEvSCYNRVqUumDzKXY4twG46r5UJo+nn/QOPmtJ
         5fytiQawsgWYRV94yy8GyaLkM8RnTDiVj95O8OyWwEf7wLmqvlFeW2dl3RN+pSFSDiKD
         evWGQ+JqlFya9MPxrGuNAskudnghGM+vfAX64rMa3PLzsPXGhSUKoX5/khblYu+pU+wx
         nEdo+Xbq66t+RsVsMD2in9seG6aysaQhaddm/CNowbF6UkYznzKDatAdJUx98tImwmpo
         pqcdBhL80QhwAKr1O/jkMIHO6BAilTD3iTVMuopeEjnlGicqUGNQ+Pv/3G3v1AGX4DxG
         /R1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Yw0rF1IOOaxC53ScCykxLWgNcUgkjkcBgA82YUCV8g0=;
        b=WPaYPe54K3IKuRNnrCM/OE+rYjTidJCUVvuTw2HDzGpbyJbmsmoa6Yxxk/2wHfbJzb
         Pj8DL9GZHurEKubbGAjdz6Oy8xvbuhuO/6rkwwVa4kN7DWft62I31fVugKUSkAer400P
         IVyKU118bGjF6KRznUX2KOH+UQ1N6lPte4h74oZkKXT++7tA5rEy/SUe9xEv1RJReCKk
         M8xNn7Tt+0PXhqGto8T0TwC0EptSxOZTBT4i2ZQejiFYTC3GrewTvngFrBVjwdLsZbAf
         XDY17/L83ymylfzryjWaR8bXdERI7zsAqXVgg+nTIValdpEsDRV6cuszND+i/Qb1yaAF
         322A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="l/kzg3je";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1677853062;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Yw0rF1IOOaxC53ScCykxLWgNcUgkjkcBgA82YUCV8g0=;
        b=GEsw4ZBvlC+kekHcP2dBCZNeN0qcqpY4GTYPTw70l30aomv61tGWH0GMM87LAoFUN6
         62104W6/G/Nw3dcyygN4CYXTkt0yolZw+rf2aVF408XrOiI/p/LRz5FpDI51kq4J21h0
         wqg2W053hF1QdJrntCE+g95h9c3wBqz004PhQLWu29DT+zEN7lo8NG6n6h2O1O2AdLPQ
         pws97xmli2R9yqVp++2ZroYtL/7V7nR+24Xf5MVY44kmw3u2KilU6Nb0xHEkSpCsZMjA
         7Li0TLidP7sWYzIfH79PX07bhG5jZ4Ol0gfPgf5zNMw2uzSHEHMRsMaDczP8kw1buOkS
         6kkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1677853062;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Yw0rF1IOOaxC53ScCykxLWgNcUgkjkcBgA82YUCV8g0=;
        b=gdnjS/cY0QncPD//2sBEnw/429hS1zTP5MWjcvvrUR9aNWv52rnDT6TEE4QQxrIWO8
         QNcGugmPNM6ThGkPQGy2Ut6QtfAwrGxPY/ZuJ5NOkSykwxEUr+uyYdXkiw5lvVf1RzKU
         XnBSg84CvHmurojV9qoDg63zoxMCrlOgiONnUuMWErJ3p4uIcwWyhWjmbJh494GXpHMe
         CN83sMXWJLQvcpwWWWn9xsi5JIe2le0FQS4QOWvxRdTILmFSt7YvXtlFljMcI0k7nX27
         Y4CeqHgSbPVTv4012ZgI+DmQiYYVB+t7psUTsT9E6puJuGUUGTBYwSZiACvDFX9bIUZE
         LBSg==
X-Gm-Message-State: AO0yUKXW1BfkidzTJygUfi87uIZtmF2STiN7t79KsF0MRuXxAb7roByk
	kYHghad/hrlMvDIE+X33VPs=
X-Google-Smtp-Source: AK7set/g+yWouzuaifDT1s5P6eHMWeC0T06uG4w4yuZK7bq2jKTFrtQMFkK9Y4+vRFjQflnvKHAr9Q==
X-Received: by 2002:a05:6102:1266:b0:412:a97:4c11 with SMTP id q6-20020a056102126600b004120a974c11mr1312448vsg.1.1677853062201;
        Fri, 03 Mar 2023 06:17:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6122:124c:b0:401:5e7e:ca67 with SMTP id
 b12-20020a056122124c00b004015e7eca67ls448352vkp.0.-pod-prod-gmail; Fri, 03
 Mar 2023 06:17:41 -0800 (PST)
X-Received: by 2002:a1f:6e86:0:b0:401:438e:6ff7 with SMTP id j128-20020a1f6e86000000b00401438e6ff7mr904460vkc.11.1677853061506;
        Fri, 03 Mar 2023 06:17:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677853061; cv=none;
        d=google.com; s=arc-20160816;
        b=jAea5T8Ppj7LOQP05w+CS7XqRq7rpTv5zBHqoOIMYHnySJBJRpskwWmMXf+et6MWcA
         S0s32Lbj7N8P1hk1JMRU4wOTOnox7onbKKdPujFrdWvwz5Zt7jOfO8We/vxxnuzzwbW2
         O6fWyfzfwbYL35o3KNdxzl5kMX/wLFH7K67nVg35St+F3Jy951nfq5yZmJoSgH9dPvYp
         f86VWs4lCJXm2IH3CN7qO3lezuw4SFYFn8tyeEfHaMY3RMG3mJjy6tIng6yGtRAS1y7L
         1lzNahYna1IBN2O6BRZ2pyWiQGpY3jSD7VMSQfMKE/F+kQJIK6PmWnsXYQV9xSaJKM1J
         Ba7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0B3hgicuXjM7bBAtA4QLzoXhHV0rOr+vQWIDTCOLWjA=;
        b=wZ/GToxdK3GpXHriduIFlipRgH0MmZLJH4FyYqUiNTHFpor7eDwONpjvAJ773BK0GF
         7evwa2Ctjta/qw+pla5tB0yVNv4rCorQlwr/7QinokAhCjzXBzRMVZ0IXwibkhpJQVeI
         N0rwt75bxTrDutg1eYz2LiaLeB3Wan/EjRuVp/Xoxil73mkLYD+jhP3GINGpa5hB0bpZ
         a1lvtJGaN3s7wn0CtdSxTOwuaxhniSu2yEPJSPsQfoix3N3SsyGI8KrWNwjFKTndYgJK
         eiLKjFswq3JPt7UlOczZbuToqLWE72TmbysQfjCXBle3Cz2N7Fyvsaz6rzpZSWuydWa9
         w+4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="l/kzg3je";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd31.google.com (mail-io1-xd31.google.com. [2607:f8b0:4864:20::d31])
        by gmr-mx.google.com with ESMTPS id y10-20020ac5cf0a000000b0040679ae1c37si157154vke.2.2023.03.03.06.17.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 Mar 2023 06:17:41 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d31 as permitted sender) client-ip=2607:f8b0:4864:20::d31;
Received: by mail-io1-xd31.google.com with SMTP id e11so1018265ioe.3
        for <kasan-dev@googlegroups.com>; Fri, 03 Mar 2023 06:17:41 -0800 (PST)
X-Received: by 2002:a6b:6a11:0:b0:745:68ef:e410 with SMTP id
 x17-20020a6b6a11000000b0074568efe410mr752461iog.0.1677853060800; Fri, 03 Mar
 2023 06:17:40 -0800 (PST)
MIME-Version: 1.0
References: <20230303141433.3422671-1-glider@google.com> <20230303141433.3422671-2-glider@google.com>
In-Reply-To: <20230303141433.3422671-2-glider@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 3 Mar 2023 15:17:04 +0100
Message-ID: <CAG_fn=XPXOkrh1tXhzvnB+eENj=JF79D9FqJV94J_kpu0u7d5w@mail.gmail.com>
Subject: Re: [PATCH 2/4] kmsan: another take at fixing memcpy tests
To: glider@google.com
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, tglx@linutronix.de, 
	mingo@redhat.com, bp@alien8.de, x86@kernel.org, dave.hansen@linux.intel.com, 
	hpa@zytor.com, akpm@linux-foundation.org, elver@google.com, 
	dvyukov@google.com, nathan@kernel.org, ndesaulniers@google.com, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="l/kzg3je";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d31 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

This is the second version of the patch. Sorry for the inconvenience.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DXPXOkrh1tXhzvnB%2BeENj%3DJF79D9FqJV94J_kpu0u7d5w%40mail.gmail.com.
