Return-Path: <kasan-dev+bncBC7OBJGL2MHBBR5TXKHQMGQE3UPQP2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 28A3B497F32
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 13:21:29 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id q3-20020a638c43000000b0034c9c0fb2d2sf9828175pgn.22
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 04:21:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643026888; cv=pass;
        d=google.com; s=arc-20160816;
        b=rylm+SQ8HhZYY+75G3MXSVKEAtBU1lzY6hUJU0ND8KRhrW5MxIH0WkD4gQry/tscsf
         RoAEff8x5XryWucunAhqwnJO1iD3uME/xFGescPpE/KeU3oLxIrZmwR8/0VYKJ6QmLHz
         9AE7VJQs6ZI/4vukUZJ8GLZuYCs7tkXAO9g07VVL5205KmaqhHaNFkL5qecluTFzcJ4V
         AqMUqg2SjF8TPFMByJqzSTuZ2oyo64hLiICDJ83q3YndWYNSUc3ZAUYBAhtkNFkcVI66
         jZopIH2PLChGs6lW6u9e63fqqmAAqb+OMizOKB4S5W0jkUyMb7egDWPDC4DDJ2aJQaxf
         mW+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=L2oDK2zDLBM8Spk9/zgcal3pNfwVhKOJPr30F+Qjwks=;
        b=AOMjNPwbnvzyoZYUT0Jm0QOvTkUo9K/DHTHR2NyGU4dlTjhdEkbfAtitr7M5cgy9bB
         jCCNnxeYKOO3x8gvAuBUL/rVW2+b6q9zICIeyTNp6GOiWw9GewX2E/JYxyOwfTiZ8k3W
         NHD9coT0Zik30B2kM6ZfYPAA0ujjLvozjWnHJMX+/3qXFmesdtPUgac79L9NtMwewGC0
         vbOtvE9reZal3YQq1zrbFkqSRFXTcsZ9hf5nT6h1h4oGAccVNvr9G/z4hv7ue7vEvHOA
         /AqqJKttjfUKQhSkVFj11sbRC7Ga7N8M2sgHyFmC6jKtWZ6TI8BqETvlkgo1xDP9mg98
         3uRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lf093Poa;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L2oDK2zDLBM8Spk9/zgcal3pNfwVhKOJPr30F+Qjwks=;
        b=ovbD6Xl3PvfHKtICsdhWUES99LB16xLSDMO79+tiwq6ppifU7Epolgr5EFCN0mCOAo
         S/L60sQ8GkYiymtIUBNPltMoPci80weVsPNAnPN+yxBsiTCW7awA+d0LiW4CvZKkJK//
         /+gqTiQuu9Qr/9z4aTJhA0UvWnIY2GwdRvWePLg9IPzrrIHsphiDbxClRNIk55Nc19RE
         afhHyI+B7fso6+8F+WwEmdjlmyHCXjhWEdDKWqJVE4wntWDr/Yv+dtsQzwk1cWDDOO/s
         D2FQBg3jME3jA6XrH4eLOT+XkKITApOa9GZG/cu4tAVA/zcG8+jpVaEsQo06MxMege0f
         eDbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L2oDK2zDLBM8Spk9/zgcal3pNfwVhKOJPr30F+Qjwks=;
        b=TXq6Oolj2dclMnj6FUhYKBSZVipwGbkadS/jpxoWwTDaEmIAfeQudiLIdEu01Pz7E1
         Herlbn+j44zp5rvbCCwRzAKNJf90TI/9hmuUixn0AK0pca9LeT66edOswx6sGejAyQib
         da+ckxCp07gswpgrgshWPSJriNu5oFmoTUTlsyGNb3yAP33OIIEpRON/QO7IFSbypMhb
         Wq43dgDZyLqgXYaojKoV4jZUcvmiLLrQJG8hl6zHFC5bs9XT7h4T1coXF2paPobvY0Yk
         g1KNI0vJB4spZLOn62WncAy85w/SMZVmDbL6AklLobHsjytupg5RLbwSZ0cbcoD9eNdL
         C5PQ==
X-Gm-Message-State: AOAM533m2RRsDU4H2P9WUyAIekAeOqyVE0yKR9V5p+SFdDTt4coqlFk8
	Y8+XFYpaz2brzenBpUuNMRQ=
X-Google-Smtp-Source: ABdhPJyUIX2tM/nlaLO4yvBGIMUfZubaMA0YVlqYuaKu4J7iGUTUAYcusLkx7tJYc+xbZJGVtNjsZQ==
X-Received: by 2002:a17:90b:4acb:: with SMTP id mh11mr772689pjb.76.1643026887865;
        Mon, 24 Jan 2022 04:21:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:97:: with SMTP id bb23ls3305436pjb.0.gmail; Mon, 24
 Jan 2022 04:21:27 -0800 (PST)
X-Received: by 2002:a17:902:a9ca:b0:14b:650c:cc44 with SMTP id b10-20020a170902a9ca00b0014b650ccc44mr1015586plr.76.1643026887236;
        Mon, 24 Jan 2022 04:21:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643026887; cv=none;
        d=google.com; s=arc-20160816;
        b=KygX08GcHCgWW+E80yQV37r/btFZ4+BvmOwpRH6AWHWnCUii4TmS9jM55aFgZX27Po
         NwN8tNQ7pkfz1lFStQLolOvFGPArMlWtA04F+pTCbdOyN/B1w47E/+QT7IW2q19YPR5i
         C28CSV2xqCyTEInM08s7/wjkdYMbJ00flzpbX7bxmUUyYHlyb5qaG1ezMdPyquUuTRiX
         rE+nMmtAB6i0mgn8pOv7GmfrnRAlJJm6hLba6Ux5PLkI3oUxExJjDnJoAxDKmaBNphj7
         OgERd4HbznZ5R9R4KeMS/yP8dsCe/x50crhhMNvuR54I8M5RLf4JkPSzOneVQSB5gJ/d
         CiNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5HHwOHpu3DODX4uWQ1+JZsd1/iIv5h6cdRibus7mBoQ=;
        b=ioDgq/ghkIbhB1CgY6bw9d8kdLTKKrPpNkiq/bw2ZR1r3AtjUduM7yBBcOhWoRzSLy
         WjqFMReEynRVfQkHCO8Gl+IIW3uysH+UtYCqnQx7eEq6zXAEQBscp6xI55VWe3vKeM9g
         grfBdBSXUCzGbMSNEtkiPl8jeX0r2lBzOlhXJ/mDkjFa8Ev1e7i8cDdhGCc1PS662f/K
         KLRNipfjnCApAbxsSK6079mfmDliwIc0nLExeS2ensfuTlRuTHtZ5V9lUljVjpnmKHVC
         Hm4YjDWaIFk9b6kgY7tqfxxpq4TUYvXGtJMDKjVAcN8iConJXH/SVQ7a4Ivgbmu2HlaA
         fMzQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lf093Poa;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x330.google.com (mail-ot1-x330.google.com. [2607:f8b0:4864:20::330])
        by gmr-mx.google.com with ESMTPS id v14si319996pjj.1.2022.01.24.04.21.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Jan 2022 04:21:27 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as permitted sender) client-ip=2607:f8b0:4864:20::330;
Received: by mail-ot1-x330.google.com with SMTP id c3-20020a9d6c83000000b00590b9c8819aso21951227otr.6
        for <kasan-dev@googlegroups.com>; Mon, 24 Jan 2022 04:21:27 -0800 (PST)
X-Received: by 2002:a9d:58c7:: with SMTP id s7mr11139396oth.246.1643026886411;
 Mon, 24 Jan 2022 04:21:26 -0800 (PST)
MIME-Version: 1.0
References: <20220124025205.329752-1-liupeng256@huawei.com>
 <20220124025205.329752-4-liupeng256@huawei.com> <CANpmjNNYG=izN12sqaB3dYbGmM=2yQ8gK=8_BMHkuoaKWMmYPw@mail.gmail.com>
 <261a5287-af0d-424e-d209-db887d952a74@huawei.com>
In-Reply-To: <261a5287-af0d-424e-d209-db887d952a74@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 24 Jan 2022 13:21:15 +0100
Message-ID: <CANpmjNNc6F7tRVn=UqLaW0WAgTr67XFm=CUu5X2D0Xbt3nKXwA@mail.gmail.com>
Subject: Re: [PATCH RFC 3/3] kfence: Make test case compatible with run time
 set sample interval
To: "liupeng (DM)" <liupeng256@huawei.com>
Cc: glider@google.com, dvyukov@google.com, corbet@lwn.net, 
	sumit.semwal@linaro.org, christian.koenig@amd.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linaro-mm-sig@lists.linaro.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=lf093Poa;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 24 Jan 2022 at 13:19, liupeng (DM) <liupeng256@huawei.com> wrote:
[...]
> When KFENCE pool size can be adjusted by boot parameters(assumption),
> automatically test and train KFENCE may be useful. So far, exporting
> kfence.sample_interval is not necessary.

I'm not opposed to the patch (I've also run into this issue, but not
too frequently) - feel free to just send it with EXPORT_SYMBOL_GPL.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNc6F7tRVn%3DUqLaW0WAgTr67XFm%3DCUu5X2D0Xbt3nKXwA%40mail.gmail.com.
