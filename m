Return-Path: <kasan-dev+bncBCCMH5WKTMGRBW6FSWAAMGQEGSIMJAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 677372F9C52
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 11:28:45 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id 4sf2205298pgm.3
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 02:28:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610965724; cv=pass;
        d=google.com; s=arc-20160816;
        b=FFrk68yBs+Y2u8GurArlzBlDeLdg00XvMF2sV9WaR1JJ8WT8AsB7TlbSB60V+5mqke
         na2uDq+QRZQ4VREzfmAd8Vt14obySpooR2IrNKVrl2MJjToBcmgurNATWd1e4tq58ZtX
         L7rWBiCYddlytEB77ZEqe2O1ugaWX5z7JJYqqOOSMvj+e+wpx2M4/8LOL48kS6fn1O0D
         t19YtxjbNQr6BvhiZe5efG39FE5Cvvm3t1NFqK/PDdq6PpF0omo6fT7dnYDxmrtieYDJ
         mNnGnyUA0MbQLyd0spDz3ARpnQMycHgjwSQPmaCO9nrFjUetmh32VFNWsB9U2d9UWUZ4
         FnSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5sjmrNQ3JTppVjFbymO8f3VxVz0agNb8NjprsrCjawE=;
        b=t5mVEBk0zZfkDQmHOrXkuxTLeUcK+dJYkL9sb575eESODleD9MTjlqBtvaxFE4sP3w
         94x0jAik7BP4PeYdlUQTLyD/IWmCCO4JVaRocRosLnJu+57hYbfpf+/n+v62zYjOVPdc
         bcHmkxMXwuFMXOkzkHe2/rUwhis8wcFeoaX4y3LSnLlqdMWQhX1pWW9SzIqengqMlKNp
         i9gTu8Wwkbsl8n//QyS4exTsgDx3r1n6F3gn0zYY6yR1ej+2+DaZ7oWTaKO2WJODRPMw
         HfzAHJ5mjmxZxqVzfk6QyCVAOp55qDkA8Apq5rdpDfFMXbpeITH8XYX7WcfQvUEGJyNW
         +mGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="ClbixE/Q";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5sjmrNQ3JTppVjFbymO8f3VxVz0agNb8NjprsrCjawE=;
        b=hz6DT/WDFdk67SC+1hcZb9WEW2JS/zH0TEdSDzzIe17RX9E04wMERhPYY2MjfTlKhQ
         TJCM88mKGfREaVie1D9K1J5vOP0bo9uT2M22g3JtP3eAyadn0t11EiP5twyFWiU10VYu
         Q+DkFXTWksXAD0IH9aQKvPJfq45vu/KL1h+hfoUCBuidWhabM7E+N2kYQqwNSVikWuLx
         5oX3I0x/SQwdVRfAV6CyTeu/IXPGXbMkjK4bnGbQ/YBOzUrvKUFIwBSY8xmeHSHBYEay
         DNm238/3vqL8Ufg/aTOjKIBNbxN9bzHbpnqVVOHA4I/YJfYIBtyvwVJ2kgxOPHuYsYCd
         Xj4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5sjmrNQ3JTppVjFbymO8f3VxVz0agNb8NjprsrCjawE=;
        b=dlm4STL332/2RtH+6PRQNcaqrt6ho1s8ATmsj1zZN7j3Is1uy8t3wmAepNVCvrkZTP
         ZlwncfpK2HWHi8wZgOSFNSXcdQ1H/pWzOFMtoyqLK3IKjZTczEQuGCPtFrK0o5QkBIO9
         1Y0X+C2EdJm/GkPBRUdea60/RkJraS/yuCAijzjcqdRgJBhiMmx2z0wD6GhTht8EgLtw
         sqm1JbGuWCIrjUOM1M7VhL/IBxik2zftxTIUqKaNmpyf/DtJFcSyarHtj0IyBiyFHrO5
         GtKQDxLaMk2JgblTwMUc/PYOPh2ROW9tTOstTljyBdiOTuG3RcbbRnssXMLFiaQuTdu2
         SySA==
X-Gm-Message-State: AOAM532nf0vPV+c5Wd79BcRZSv09VvupycdrjirO8lbCEXPfNXSnTrQT
	Ibh4ZJ1u64yI1YulbCFBxbI=
X-Google-Smtp-Source: ABdhPJwJkTct1KRf+2M0SSMwvCI4FTwA4/BJJC1Us+5ucjpup6qV2INl1FQQka/n7gywBEoWsF4HkQ==
X-Received: by 2002:a17:90b:b0b:: with SMTP id bf11mr8351642pjb.122.1610965724003;
        Mon, 18 Jan 2021 02:28:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:5803:: with SMTP id m3ls6334372pgb.3.gmail; Mon, 18 Jan
 2021 02:28:43 -0800 (PST)
X-Received: by 2002:aa7:804f:0:b029:1a9:5aa1:6235 with SMTP id y15-20020aa7804f0000b02901a95aa16235mr25434480pfm.1.1610965723482;
        Mon, 18 Jan 2021 02:28:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610965723; cv=none;
        d=google.com; s=arc-20160816;
        b=OKAmrGaX50qsvg2LEUHaPnv5Lxcr1seJGLn91oBy0lurSQIFi7eIMQ7yHBxdRQSlfi
         Tib2rLmgU2WiFs4zMk8txGEp47u3PULOLo+gCgQ1ZuP2X4RrnYiSIC0gIB0TpsUvaoIj
         qRFEoqlc1jua0akWFc5fz6KtibZsIMdp/wS3BswmLjObzPewiv1f77kvNU010wIVXNvy
         +/yWafZv1tqSpKkOs7yozKqetGAuwPLVCszU1P1rOxbfK8VkAw9btbU1CH/jhPj3HEFo
         aFsrnHktYe62ETvlDK5m/TUR0U1LSYwtFjHffgn0HVNR8nKmoa+68Wy/Jy2L2Q7aBlTY
         1eGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OYvmTRg9VE7k01lzg0q32naiEw2p5pLxGQxdorBtVnw=;
        b=Obve6k1BCPx5AkGRbFi+4XmBNNZUE2VA7fewR48Jg+OOptR750STfPbWS5JJGbixeF
         /RdwB0VRk9bp387PN98qp6yw0I0BFlKvZGHfwuQkzP+sNSKZ4l/y21Rp/01ZHBeo42Qk
         DWHClqcTtAPLJmQL6WuhkXuqJXjD0YRpP/SU9rYuAu4FXfSnRSKYvczGuALZ9eCkzPKN
         QRG8l5HjPHzJTXFie2TKL5a/kRWJZ4DzUfZWf2/9C1kBoJqB1p8aidarNQ5oITa/YqCK
         +3UgMHiESuN9JQDxI3OEOgcuvR2kt12cpFo5b7UV2DBFcv9WROPo7W5x1Drj5uvxwYSb
         D6Yg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="ClbixE/Q";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72a.google.com (mail-qk1-x72a.google.com. [2607:f8b0:4864:20::72a])
        by gmr-mx.google.com with ESMTPS id ci6si284244pjb.1.2021.01.18.02.28.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Jan 2021 02:28:43 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as permitted sender) client-ip=2607:f8b0:4864:20::72a;
Received: by mail-qk1-x72a.google.com with SMTP id p14so18179646qke.6
        for <kasan-dev@googlegroups.com>; Mon, 18 Jan 2021 02:28:43 -0800 (PST)
X-Received: by 2002:a37:a747:: with SMTP id q68mr23815802qke.352.1610965722962;
 Mon, 18 Jan 2021 02:28:42 -0800 (PST)
MIME-Version: 1.0
References: <20210118092159.145934-1-elver@google.com> <20210118092159.145934-2-elver@google.com>
In-Reply-To: <20210118092159.145934-2-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 18 Jan 2021 11:28:31 +0100
Message-ID: <CAG_fn=U7C16Nx6rCfo2eN0yOxOjOBdHr7UU5wmMZtuCVad+ZnA@mail.gmail.com>
Subject: Re: [PATCH mm 2/4] kfence, x86: add missing copyright and description header
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitriy Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="ClbixE/Q";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as
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

On Mon, Jan 18, 2021 at 10:22 AM Marco Elver <elver@google.com> wrote:
>
> Add missing copyright and description header to KFENCE source file.
>
> Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DU7C16Nx6rCfo2eN0yOxOjOBdHr7UU5wmMZtuCVad%2BZnA%40mail.gmail.com.
