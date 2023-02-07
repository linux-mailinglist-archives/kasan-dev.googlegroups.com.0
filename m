Return-Path: <kasan-dev+bncBCCMH5WKTMGRBQ7JRGPQMGQEAKUOWTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id A772468DD6F
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Feb 2023 16:56:52 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id m8-20020a5d64a8000000b002c3cf0250e3sf1726639wrp.1
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Feb 2023 07:56:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675785412; cv=pass;
        d=google.com; s=arc-20160816;
        b=fZj3tVYBdDTS5bvo93/j9R1BhBOJ9WgRweqp8qzQQgTWokFXHCUP/7IX46aMneK1hn
         OPsLfXwDmCaxGeuEMeqQ9zjqJBbj8XgQdGR+BHSLxF/ZYMXTU2iedj1cu+TqfcYBRQMl
         ycPujgl2QgKnlBpStnCikgXnC2NlefRKpedifaXkRsT4Xo+hbIk67c3TRvlicy9T4Y6B
         9jgF6i82BfXSuXlg+jvjYn5XmF05Cev8sF1G7tLm9YbS7j4WuxhPobAsCQpi431fE5Pg
         uYayN0j9eJG69eZ7tPr5ReOvsHCFuDV3doCZEV3E1MMYVdmynoJGlvqbjQetkdfV7ipO
         z8pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dfDiX5PZak8FugSDtybACJ/SPSZbzZSjRXH8rfk9fqE=;
        b=Urx3lbdi4DShGBaU6qO1HDeGCKy1JFQLT5ZyuVhdn9XsZNN9VUTT9RSIRt2u2Gp4v9
         JH0wjbkNen8x9NbuZPZWnhjCbcd7T464Y4ajuTKt2mCWzwcw8SvNU6sCRBwDSOSRqrL4
         8UECZmZVK1PLe4YOQTKdP0qfC6AP7uF3hjjbDTz9NULUA71SgPQJJyk1FZn1657qur0t
         L9P8N82qkQ3kXMZj+tcP0bEjlfNiHH5G32Lodu7jr6oat1fmwyrMWTTp0ta64KNj8ffh
         BCniI6zO3Lh6N4GtsMWAafyGBitvWGBWNcfTJuiQ70hRpfFnKQ29xXlsm7509TlbHnwx
         Qt0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JgfNzpS6;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dfDiX5PZak8FugSDtybACJ/SPSZbzZSjRXH8rfk9fqE=;
        b=PKehA+rYkxeM3izGH7QABsL3TX2eiydqN4CVmrUM+RKoffC0vafAlpHgho0O2kfe73
         biThetOEFWSLCnwqFLNRs/kF8d4uLda1A+MJsLW2dHiCUFB0VIk0JgQhBNTGLNc8uX8B
         FPHSWLMUKTdYPHNqe2gbK8OsE+ED9vIKncVsJY9W+y7o2l7wFrIsaC2QEUryM9e+lyPm
         oQm4rk2XcfJQhw26tL3kAY9nC8pDs7WRWWuWsT0kVcsat0cENAS5bkNZUSglveoDNS9b
         QEF3dqsaJMNzfzu6eUHJhy1SNqGPgeSqHsJFjtuBL0p1jANViMrE9tYCKbdUBMqOUy+5
         IRIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=dfDiX5PZak8FugSDtybACJ/SPSZbzZSjRXH8rfk9fqE=;
        b=gKKHEViQxfm/T9EfNqfDFO04yystFPVRCoZQnlSZH6DZO6LEzckN6MaQB1kR9Jm8JB
         lXnqM411C9/LZpp9uVfVIau2RBM54HX2t9Qst9LZCWUpXJSB0UwH7JSxzzUd8pD4tOTI
         Xs+Bm8mZiwdsW7aCQTebYLEMkkZt8M2sujN+oO66GKN8F3du/wiT8opocYJdmPMB72zn
         +WevQjhpjuVRP+DlIPUt6CJVZjF/UqK4Hfwbf/PTNw0oi24xh5sQAMukFwIKDx6G91v9
         v1/FCsqXHqYgNu2hQjolA8j0QejSqIAvDwiTX7Kx4Z/jKEGrTFjx0mPNlTAcSoOMf1FJ
         4/Og==
X-Gm-Message-State: AO0yUKWtGh94nOF1w3Yaxxt3CHqaA1uetgs1aV2uTDCxlElzP+WRAoKv
	Ngy0O04zPujdNQu8fvzqaJY=
X-Google-Smtp-Source: AK7set9RfUrb/ivWcD8upWUZ4rK1mRxNE97TWM1IPnIyBuQZ4QTVpPc6aK5Fnl7aaqdVSs7ir6Prsw==
X-Received: by 2002:a5d:4987:0:b0:2c3:f03b:f98b with SMTP id r7-20020a5d4987000000b002c3f03bf98bmr140670wrq.385.1675785412050;
        Tue, 07 Feb 2023 07:56:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:18c3:b0:298:bd4a:4dd9 with SMTP id
 w3-20020a05600018c300b00298bd4a4dd9ls22067732wrq.1.-pod-prod-gmail; Tue, 07
 Feb 2023 07:56:50 -0800 (PST)
X-Received: by 2002:adf:e5c3:0:b0:2c3:db5b:7280 with SMTP id a3-20020adfe5c3000000b002c3db5b7280mr2873861wrn.56.1675785410845;
        Tue, 07 Feb 2023 07:56:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675785410; cv=none;
        d=google.com; s=arc-20160816;
        b=AAcK6n/oKTCXkcSs2FuvacuIIyQ/Xr4FQRmsbBs7aVX7MVHv5+RFOSXF0h/GqCApAo
         imgh/AMtqiuylo25TZMqc0rIzfaFEiIGu+Wt08mTWTW31wNQ/1Fg9S/d2GztWBFnVjcd
         ZfwdjaOgmAu0RiIClJ4lj43mvl1BOOgDdU9CIUIcjjC2+079aMNGNoHxK1RBow0DZlcD
         G1CbIpaRrS7/MOEJGjyUxxKXmSCzM5ySZkL7uXwFEMqfW1bt9IUFkNGtsYJb3DjmfgzH
         9PMam6iJSKW4I1W/61PpK65KcE5lKq56KSFPtXX7X5zPSHLNASwybcHrUvrXfb5XTK0D
         JhgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UmeU/kdhBO7XqGPtfKBv9yIOYYG4GxNWHmPeVymMlSk=;
        b=Z1mkxDT3onCbD4wkD5aKXmGjjRYYNuhjZ8z+8Cuh1iBu1KwPg8qss5aZ7ba8Oo+Pqw
         ecz1VGqHZ5wsSqAfR8+/gmTD65j1FB157Ks4FKvV4RwPQC4XyxHv9mp/9zBgxjAAVwfC
         8khSm19hA+3b76uLqWUS/dOcaYt9CJr51M7sMFcSppozCvecOp0ZTxTW8J7u8x61a7cS
         dmbRRclO+Vr+1qCcRqThV2ZeadqE0Nwa8Ih8RNTtzUXUAhI3o+97btN5FQ3Fg5fVxERq
         S3feCFJaTTCB/9MjSspzGQXqkZC7e8ZDzzWx02WFGMDRRcDGSPdZY6UhQqwqlsxbmQST
         oc5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JgfNzpS6;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32c.google.com (mail-wm1-x32c.google.com. [2a00:1450:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id bn8-20020a056000060800b002bddc018216si603659wrb.1.2023.02.07.07.56.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 07 Feb 2023 07:56:50 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::32c as permitted sender) client-ip=2a00:1450:4864:20::32c;
Received: by mail-wm1-x32c.google.com with SMTP id q8so11359092wmo.5
        for <kasan-dev@googlegroups.com>; Tue, 07 Feb 2023 07:56:50 -0800 (PST)
X-Received: by 2002:a05:600c:354b:b0:3e0:c45:3456 with SMTP id
 i11-20020a05600c354b00b003e00c453456mr438239wmq.44.1675785410384; Tue, 07 Feb
 2023 07:56:50 -0800 (PST)
MIME-Version: 1.0
References: <cover.1675111415.git.andreyknvl@google.com> <5456286e2c9f3cd5abf25ad2e7e60dc997c71f66.1675111415.git.andreyknvl@google.com>
 <CAG_fn=XhboCY1qz6A=vw3OpOv=u6x=QBq-yS5MmA0RbkD7vVJQ@mail.gmail.com> <CA+fCnZfJdjgwoONLXcq4qdbMcJvRavhVp021XNM_7VM+4pUGyA@mail.gmail.com>
In-Reply-To: <CA+fCnZfJdjgwoONLXcq4qdbMcJvRavhVp021XNM_7VM+4pUGyA@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 7 Feb 2023 16:56:13 +0100
Message-ID: <CAG_fn=UuJomZqSDc-WiMipW_r+v_o8na2YRtMVUo5=7vCYUV1A@mail.gmail.com>
Subject: Re: [PATCH 09/18] lib/stackdepot: rename hash table constants and variables
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=JgfNzpS6;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::32c as
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

On Tue, Jan 31, 2023 at 8:02 PM Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Tue, Jan 31, 2023 at 12:34 PM Alexander Potapenko <glider@google.com> wrote:
> >
> > On Mon, Jan 30, 2023 at 9:50 PM <andrey.konovalov@linux.dev> wrote:
> > >
> > > From: Andrey Konovalov <andreyknvl@google.com>
> > >
> > > Give more meaningful names to hash table-related constants and variables:
> > >
> > > 1. Rename STACK_HASH_SCALE to STACK_TABLE_SCALE to point out that it is
> > >    related to scaling the hash table.
> >
> > It's only used twice, and in short lines, maybe make it
> > STACK_HASH_TABLE_SCALE to point that out? :)
>
> Sure, sounds good :)
>
> > > 2. Rename STACK_HASH_ORDER_MIN/MAX to STACK_BUCKET_NUMBER_ORDER_MIN/MAX
> > >    to point out that it is related to the number of hash table buckets.
> >
> > How about DEPOT_BUCKET_... or STACKDEPOT_BUCKET_...?
> > (just bikeshedding, I don't have any strong preference).
>
> This is what I had initially actually but then decided to keep the
> prefix as STACK_ to match the stack_slabs and stack_table variables.

Ok, let's keep your version then.
Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUuJomZqSDc-WiMipW_r%2Bv_o8na2YRtMVUo5%3D7vCYUV1A%40mail.gmail.com.
