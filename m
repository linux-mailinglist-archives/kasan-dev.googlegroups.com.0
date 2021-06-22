Return-Path: <kasan-dev+bncBCCMH5WKTMGRBPG2Y2DAMGQEBMALMZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id B43C73B0031
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 11:28:29 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id n84-20020acaef570000b029022053bcedd7sf6215904oih.17
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 02:28:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624354108; cv=pass;
        d=google.com; s=arc-20160816;
        b=gIFzottRir44cCpBvkGWExE82AQjMrxrcXo6vBkB5B5MgLgQ/4VWNm4icDpr94egDT
         3GBToa47S5lJK9enf8B6IlaLnlbSHz55dIs9H3y5S+ZiR/FuJHj2muJmF5Sc10Y+trAE
         v4sBmPmCXzFtO2bbpaqWOsbPu3fm3QZGH1SMNLAN7WmZucQtGaW+lRjHi38J29owzkwD
         laedtHZC+PYTaQoCRZnu7Cdg5o7vJpXZfPBYTB3qvZtseZeLlU3HSl7/nOvm+S5wbU2J
         xamtVio7EbVV+TYoy4YceEnSAzVAfozf4kwyzHVEB8YJ6vV9RvwvJLmg/HtwBsMMV5vi
         7wAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=YglTJ+BnmcbLERyn1Hj7hMI5/fUgxgfebRtgwttz2fY=;
        b=SqWdrbVx0hBnjNq49Vyc3pRBe7osaBBntUiadVXEwS0IV9jlwVuIy/8ytKWQqGo0Wx
         nNdGCW47Pi0STadNHNXx7mc0mGmhzT5Cq1iAyj9novFCs09FKxwObtw5z5oKcb7alKH5
         po+ikEgtdasR5jRvdXWdm3ufVOBJ4Yw26BXktZ5M4xdlwa5LCKpuwK/kSF3aIEUwYNNt
         QlZFWVr72f9KvvglnpnbPTkJY8mvNSqFio01FETnimdpd3a78onbZlE9hGCKVlAT4a+k
         VrDE1bB4i69C73B8WHevyJb+a7EuOw05GGt5XNParyMvUsK46iD0tjDyFxlu0D6shHgu
         zsOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UuHF70wn;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::731 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YglTJ+BnmcbLERyn1Hj7hMI5/fUgxgfebRtgwttz2fY=;
        b=UUSQcg3fBZzMLVp5plVRm54/T8aaqsym0S1lryifjyhKetkMn47LSn4lblchSe+fX4
         t23HMKHOq5ODiXGsjKF30cgqJP6/pBWO4cHtVSaskRfcgmmopQNfkC9viJkH1+5KiZ4A
         tdYk5CROfMnbXlxjEz/mTyItVktGSdde/GgrSn0tRNtIwtGaji1rQIvk/VTHv9xSWRyU
         wheci2V0t/XmNgS/8xH6bXfv2LTG0aiYB1NugIhegx7b96JwClk9TSjtdmK0aWrefpd+
         +FW9FJKhni961W+sTFlwrUKoHonFUJOUyUBp7as3qfDT5q2x04qFXK/fj3v6sLhIQjJg
         3FzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YglTJ+BnmcbLERyn1Hj7hMI5/fUgxgfebRtgwttz2fY=;
        b=Dr5/EhyJmy7HDAyKnRRnBjTx8+EUpkLfKmG1dyM5FsvLlWc2f3WsGpmHCvq7rO91rM
         Nw0YPSogAfFkCpLF3Ew8TP9rcoTpSjp4jK4x/P6srx1qkEeHpZ7R8l1GN4feq3JGC3wZ
         LEvvQhvnTe6byJ7pDZXKScxUq9u6w8/hVBesy+B1HKDbbZ8Kr2K3bxLb8n+Bt3j9Kzjj
         UYIN0VqogHBsJU+HAq0h7sSL7b0S9XYkdDtV9Zd7elWtjxP6r7Dr4yN4EWpUlcYGXs8j
         n60AhejrPlEZxXm8p+mKfjSfjnbQkCPD+Vf5vC8K+e2WJSo1ZtCk720sxyoIMGtxwTvQ
         6yvg==
X-Gm-Message-State: AOAM532ODzmFBvjFW+aG09oa+3pltsrGsAxuIWSKDKPIqRih0esHaMQZ
	e6QBuQDimEjK7XnmStu2JKg=
X-Google-Smtp-Source: ABdhPJzKZOwWiRfw9z+SGCNBQjeWyFGUg53gv5NwZk7KpLO1ugs8Uj0Lr9DgA0X7Jaz5m1idpz5ExA==
X-Received: by 2002:a05:6830:2649:: with SMTP id f9mr2270578otu.179.1624354108730;
        Tue, 22 Jun 2021 02:28:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1310:: with SMTP id p16ls7421373otq.10.gmail; Tue,
 22 Jun 2021 02:28:28 -0700 (PDT)
X-Received: by 2002:a9d:147:: with SMTP id 65mr2192789otu.315.1624354108394;
        Tue, 22 Jun 2021 02:28:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624354108; cv=none;
        d=google.com; s=arc-20160816;
        b=Sc+AoSqwLMP/fKTqZcRS+AkByzgkwyXHaQn5M+hjxI/Fo3Pd/5bYSpMp5Vc9cvA22c
         bnDfSOlNKZkFUvG9LcgaHqBwjLV7/SOmI0yzrXFScpzbET8c5Bq8ej5nmg6SIWTwCsIa
         XNz6PSib0rQSoip31yDVYiNatW1djvD1MbpZuUX3COVs2VoNxVZ//FiQ1Ta3TEsxekPW
         aKEw/yedZbi9fqnXU0NdMvQYaL8rlaxj1duvV0BKzBbnS7VATUaegtUVXJNrE62dyhyt
         OXr5Rl7H8TxSlKTG+QVM1oamY3YnxUK9PJ7kw85QeYAHc0YaKRHdeFLT1nmhCX9TA8bq
         aCVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=E4DQbfXpC/jltQHrmKqBHkqXNz4Cwyp0eCIHowO6dsE=;
        b=nBpc2OtS+VCXr9Cf2oIWOwf7A1o6dtO2QbBEs2eceJLC3eMndQtumGT7QkmYARLqrq
         di7XYWQoDN+4sKKyk3xThQW9oC0DgovQxqYSO6r6095Phzt9PiOoZKGvWn0tA3SaKKbD
         73dKF3OfVky6xazhrpvtijFdhsuZDbkoTH5YjCfX1s26VqlZS33EUCuGjCrexNtDzLFp
         p4oc/K+D4h99K88Q1nZLepkVh8ZvaKjFtjBxI2KaCw8g1S2PqhRLDq88g0VwNlsSmZzE
         4SQRD7SI3iSwGMttyyHF/3ajI1O2m7eny06q1anjAUJgpGXqsULdkrHQeF5d9zPqSa6T
         BYng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UuHF70wn;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::731 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x731.google.com (mail-qk1-x731.google.com. [2607:f8b0:4864:20::731])
        by gmr-mx.google.com with ESMTPS id g12si189308ots.2.2021.06.22.02.28.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Jun 2021 02:28:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::731 as permitted sender) client-ip=2607:f8b0:4864:20::731;
Received: by mail-qk1-x731.google.com with SMTP id q190so35074530qkd.2
        for <kasan-dev@googlegroups.com>; Tue, 22 Jun 2021 02:28:28 -0700 (PDT)
X-Received: by 2002:a37:670a:: with SMTP id b10mr3184065qkc.352.1624354107698;
 Tue, 22 Jun 2021 02:28:27 -0700 (PDT)
MIME-Version: 1.0
References: <20210620114756.31304-1-Kuan-Ying.Lee@mediatek.com> <20210620114756.31304-3-Kuan-Ying.Lee@mediatek.com>
In-Reply-To: <20210620114756.31304-3-Kuan-Ying.Lee@mediatek.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 22 Jun 2021 11:27:51 +0200
Message-ID: <CAG_fn=UTfR9yKrkdRDjxFn=vgR_B7kzytm9WDWT14Gh0PLXyJg@mail.gmail.com>
Subject: Re: [PATCH v3 2/3] kasan: integrate the common part of two KASAN
 tag-based modes
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	linux-mediatek@lists.infradead.org, wsd_upstream <wsd_upstream@mediatek.com>, 
	chinwen.chang@mediatek.com, nicholas.tang@mediatek.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UuHF70wn;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::731 as
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

> diff --git a/mm/kasan/report_tags.h b/mm/kasan/report_tags.h
> new file mode 100644
> index 000000000000..1cb872177904
> --- /dev/null
> +++ b/mm/kasan/report_tags.h
Why don't you make it a C file instead?

> +const char *kasan_get_bug_type(struct kasan_access_info *info)
If this function has to be in the header, it should be declared as
static inline.
But I don't think it has to be there in the first place.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUTfR9yKrkdRDjxFn%3DvgR_B7kzytm9WDWT14Gh0PLXyJg%40mail.gmail.com.
