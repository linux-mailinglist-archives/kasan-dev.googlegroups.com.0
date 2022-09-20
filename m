Return-Path: <kasan-dev+bncBDW2JDUY5AORBAE3VCMQMGQEPZE7TKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 343975BED3A
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Sep 2022 20:59:15 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id z24-20020a056a001d9800b0054667d493bdsf2203689pfw.0
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Sep 2022 11:59:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663700353; cv=pass;
        d=google.com; s=arc-20160816;
        b=l+JJJyhqLeWCyE65tnuaAtH+8EzE45IWAfesbvhIsaWLkdG/0eVXkdziZMyqHHuyEs
         VkhfSEoMasGpOBmg5/EYhhVY/7aaK0o79EWrK1bx+t2mdEqoLNeIGH8ksfu+qzbOeYHf
         Xx+FW3fkRGUc4AY0Rs9lTyzM85xSJONGKz38ahcFV6ddR4RWiwizlVvns3/InKLDUpf9
         YfiI3na9fiioGvWCK3SxDnxZaWURiLoV3Wyok93vIGzAOLJFfdFHcw7ybLb8xVCrYqG/
         wRyMnz9ihFw5QTy8M1+lXFNUgUMgENZzwQct1HNaexyEs4eIHUR/jMFFaoH0gwqvvdru
         KfDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=miQIVgXxG2nUOiU57+9/PtRZsUnhusC67YaeuD83+00=;
        b=IOk4TuC4KsztjwmvIT48K66gizknylWa5wOKD1vbXmDE0qq93hfVnu/U6JQyebv+1q
         /aY+ZTe+SLMzReqK0guGRUqCQTcz0xesLWeRcE5R3Lxs9XoAvChbsixpPumJovOwKDY/
         O7FrZ0e3FL6900P4SuO4U+iINYcg+zt6v1sA9K7kVUXz0HLO6s9dA6OqH+YKTpKwH2zC
         JSAR/aiirrx2W07qFPubmaqfvpe0dVV44ycJWnZ1ukNd1o67YVuIdDcU0HCDg7mkJDtQ
         66h2a4FNxzcS0lhrjWVId8J/RU+fMwYhnJtQiPsF0kkmJlycOM2OLGJsZGSQPRygtWwk
         9ePg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=NHt3gNnP;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::835 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=miQIVgXxG2nUOiU57+9/PtRZsUnhusC67YaeuD83+00=;
        b=UrXYHAVrCY0wbqpVcFrlrSdlhTfhe4Vg8tIalooXlhW6zaKrvd2Lzhv6LjFhyrgCfm
         Nsg/ye4GIbWGQ+90xGstLxfyoNJPCle2Du9RwNbwFjBIrgL3+JNYessTztfFXuRGVt4G
         LdZ/LYZ/L4PjZKLmZGMpMJnfHUu8mvacvwMusQIHaax+2oPhT7pxCjLmkYgFl+QTJMgO
         MLyMc53NBTF0AOci0yv8Vpd/x9J7b5KySo09p0kp5FWKSqrBiFEJ+OJUFEvsLOkb/l94
         51cW/mV6KaVFpVIzPn7/D/3BLP0+grADzY6C6kvfqOnnekxJW/Lwdv5TT29wFC9DMgwi
         V0uQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date;
        bh=miQIVgXxG2nUOiU57+9/PtRZsUnhusC67YaeuD83+00=;
        b=E4LGslXvMv7j/OEvZZy5M8MQ9osgeTm7w0VS4wCNY8nG5lbSmN5uFm5qMwrZqvPxaf
         2gqTKfmLEliCY67Cbd6mLtC+vdS/WuE/HH+qAvClxJqq8WHkz7LhtE1vHnNqoawUmwbT
         UAhc5sRCm0aaqrGIGdVeK5JY2XYJXV0axKIj+eG7CvfD8NXC6BkFTetDPAhEAukfmtJl
         41caPNTyf9WnEKVLoVXpy0q91o97mLR4T9lWrXx95mEh0QHVrzeLjTkwx6uDjmWaGC8T
         aqmO/iLTumiOUVwCFcVq8c/whDKk24iMW/FwgQeXty91lHyKXIOuwqAoqAJjWgwJ6g6X
         kzkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=miQIVgXxG2nUOiU57+9/PtRZsUnhusC67YaeuD83+00=;
        b=tM/qYGGzdjbPKvdn/D/jbKReaRYH6Q356KAX5Hc9t4tZ+D33weA4p9Nks4+zFNMT6k
         /2AU3caHAI5BUeCvVllmVH0iQcqi0/QoNQ57Ztz7kiOi2aaoOk9l0wX3YX9sWJg6jvSs
         9aGSGdLsVnhukonXQyz8I+hflF1I+dPOwOAcL77j5uGGcIpbRvpoVpPfjUOp6deRwZYP
         5a9PQU0kixEa+Du5HOPNgbwcxKZv86b/OYxBgs5JB4hG8QYY1qLPC01BpuSPFOk95dos
         fCgIxFHs6Y8SJ/uotJ4TJhHeEiEQYB8Cy7DFqQCqj14YfXtTXWAN1zpXiaKl206vE3Dk
         xbUw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1w3nzfEsBMljsrsiuIfDn1fj2zjqWvIWMkaUeo1U+0QtO72RWP
	X9UqhCAStQ4vDrX37sbIW5I=
X-Google-Smtp-Source: AMsMyM6jzL+kYvFLmG9wDY7JyQCvzxcfVBLNc0DQCHSGsVaecepL/BMky1UMOQAFymj22A5IAb+NuQ==
X-Received: by 2002:a63:db54:0:b0:43a:390b:716 with SMTP id x20-20020a63db54000000b0043a390b0716mr7431540pgi.360.1663700353054;
        Tue, 20 Sep 2022 11:59:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:7345:b0:1fd:d003:c982 with SMTP id
 j5-20020a17090a734500b001fdd003c982ls381796pjs.2.-pod-preprod-gmail; Tue, 20
 Sep 2022 11:59:12 -0700 (PDT)
X-Received: by 2002:a17:90b:1c8e:b0:1f7:524f:bfcc with SMTP id oo14-20020a17090b1c8e00b001f7524fbfccmr5374929pjb.132.1663700352355;
        Tue, 20 Sep 2022 11:59:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663700352; cv=none;
        d=google.com; s=arc-20160816;
        b=w8Dw5Pxcxw8/dqQoKb0XBQln8lhjC4OOQuLzH4cVyLr+LcOm1zmRKrpoT1TBIx+Rxd
         tE/bUo4UV9ZE7lGgUQu651vL0BcJyyFH7Nl6dzfZIViF1w5SdiJ2UfzPphUOesfJksrn
         HdRaOte9R59Rqr90F91W7I40JZE3mPpDsIjNSzHdfWUby01CWxsc6wFJ3hJoSt9R/gMb
         WqNDTEsY7GgjlOMNOe6mfewcKKM8p5U4INmLqMiG1uCWwqnrY7JT8S17Dm4J/3dpczDG
         qZuLP9jxoEezkhZiIdJCa6J77LvsMj8/wttg8GK+0Zp7EFHBGGqk05ZdgZL1N3dGhDZ+
         9aEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=D8dJcpZD+yJJTRrjXKaOEFQ0b3WoLQpt8eE6p+5Y5WA=;
        b=kog3BAnJFWwBPV3d//Hb60eupunnczz2A6zBvuKa/T5PR0SaUyiCjsAV8RtCyzAZoW
         3pr7JnfRZuGBzcHlc3q27c+YvPhKENmFMB6XoBc/+vbcs12J2wqMmN+BdhqxPDh2ahfT
         DLoSeaAepbctqB73orc9+guaLdO6SNzVUddbUr+2Wp03lEkitSUs3dHCANyzcNtxHLYx
         bk4Mh3Zj8Bq1InrgaeNlCJHX+F+Hz9tt9GaBdklqYEih0SsEYGLWOLP28jlKcwSQLdJ5
         ohVnEbIQEYllb5Hr3rtLDJaCDdVbNzPY6A2aqWNlJRamF7wgeyTO+xPQdaP7Ijyomyig
         8o9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=NHt3gNnP;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::835 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x835.google.com (mail-qt1-x835.google.com. [2607:f8b0:4864:20::835])
        by gmr-mx.google.com with ESMTPS id oo16-20020a17090b1c9000b002002faf6c49si14467pjb.2.2022.09.20.11.59.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Sep 2022 11:59:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::835 as permitted sender) client-ip=2607:f8b0:4864:20::835;
Received: by mail-qt1-x835.google.com with SMTP id g23so2456090qtu.2
        for <kasan-dev@googlegroups.com>; Tue, 20 Sep 2022 11:59:12 -0700 (PDT)
X-Received: by 2002:a05:622a:14d1:b0:344:b14a:b22a with SMTP id
 u17-20020a05622a14d100b00344b14ab22amr20408437qtx.203.1663700352038; Tue, 20
 Sep 2022 11:59:12 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1662411799.git.andreyknvl@google.com> <CA+fCnZdok0KzOfYmXHQMNFmiuU1H26y8=PaRZ+F0YqTbgxH1Ww@mail.gmail.com>
 <CANpmjNM3RqQpvxvZ4+J9DYvMjcZwWjwEGakQb8U4DL+Eu=6K5A@mail.gmail.com>
 <20220912130643.b7ababbaa341bf07a0a43089@linux-foundation.org> <CAOUHufZg_FfKvNAsTmJvWA5MoMWQAjSpOHvWi=BAmsUPd3CZmg@mail.gmail.com>
In-Reply-To: <CAOUHufZg_FfKvNAsTmJvWA5MoMWQAjSpOHvWi=BAmsUPd3CZmg@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 20 Sep 2022 20:59:01 +0200
Message-ID: <CA+fCnZcdfvHBhN3NjL+nybm8s1Tte+kMB_X59NMsBXJ_OpCa_A@mail.gmail.com>
Subject: Re: [PATCH mm v3 00/34] kasan: switch tag-based modes to stack ring
 from per-object metadata
To: Yu Zhao <yuzhao@google.com>
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, andrey.konovalov@linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=NHt3gNnP;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::835
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Sep 19, 2022 at 10:08 AM Yu Zhao <yuzhao@google.com> wrote:
>
> Hit the following with the latest mm-unstable. Please take a look. Thanks.
>
> BUG: rwlock bad magic on CPU#0, swapper/0, ffffffdc589d8218
> CPU: 0 PID: 0 Comm: swapper Not tainted 6.0.0-rc3-lockdep+ #36
> Call trace:
>  dump_backtrace+0xfc/0x14c
>  show_stack+0x24/0x58
>  dump_stack_lvl+0x7c/0xa0
>  dump_stack+0x18/0x44
>  rwlock_bug+0x88/0x8c
>  do_raw_read_unlock+0x7c/0x90
>  _raw_read_unlock_irqrestore+0x54/0xa0
>  save_stack_info+0x100/0x118
>  kasan_save_alloc_info+0x20/0x2c
>  __kasan_slab_alloc+0x90/0x94
>  early_kmem_cache_node_alloc+0x8c/0x1a8
>  __kmem_cache_create+0x1ac/0x338
>  create_boot_cache+0xac/0xec
>  kmem_cache_init+0x8c/0x174
>  mm_init+0x3c/0x78
>  start_kernel+0x188/0x49c

Hi Yu,

Just mailed a fix.

Thank you for the report!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcdfvHBhN3NjL%2Bnybm8s1Tte%2BkMB_X59NMsBXJ_OpCa_A%40mail.gmail.com.
