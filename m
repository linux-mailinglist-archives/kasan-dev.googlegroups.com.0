Return-Path: <kasan-dev+bncBD52JJ7JXILRBJ4YWCRQMGQEEVZUXJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A1DA70CFAE
	for <lists+kasan-dev@lfdr.de>; Tue, 23 May 2023 02:43:20 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-623998c0d33sf28671686d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 22 May 2023 17:43:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684802599; cv=pass;
        d=google.com; s=arc-20160816;
        b=mxcuiLHLiRsD3IIngiF8nIjALfTGFe6tgSAN/ouowtyN0xU0YXwF9qKxXI9CrxE7aD
         QTZxAlmo75Qhpl9HznmoS4ozPoRfcPPkBMKegLyuHIL4JCODKNNYOQZ05v0GcKbzee2w
         +rtTXWS6KstAM5gSqOlNmcBxbzEs7FzNSJ2BvBLtgFE3tdhS/CXk/FoQvhgy/cf6MTpg
         m1Kzy+4TOnOnxYfIjkyeh7h7f+cEVQmGWFsaCbEgH0X4ZwYSHaig39mEJGx5fzAzwXa0
         tZc/N8zkmToRsANdZimYxVQBusLgXbwsKvhrRORAgWuObdPd4ZIgtJrCChKXzzErYRgT
         MxhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=f9G5O2/BZNmb0eHsnq2ATvSa36uhU4HNGz8hkRwg9Yw=;
        b=vS9p2TX44WrzSzRotn5WuEejN0/7j3CZCnQPmqSpzhaLGkwpG7hZ/yzJwLtmApjbXY
         9E5ZieZ/RkGD2Cd+dN5PKYUBfUb4OEEp9nno4DQXBdKb78hmRtqOs1g+ay8QtbVCk/LU
         64jaFSaF0W+Ryb+SLZ9yWMS/5QemM4Djr1f12eTAwZ7VPDypBcPWxqcoqAwrJqJeaQA7
         28nVdPSb4l+2//NM8JF0NSJ3WxwlO/q6sWWBXMxyE9e+HFmrcHymVrAvE5UaAZ167QJI
         GKKv+2gTjgzm6pVgsVLe4pbf/ypcL9G/az5YmcYRQxkUdkTqg/Nm/xyZGxPlgmDKK6ww
         sadw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=GVCKc+6r;
       spf=pass (google.com: domain of 3jqxszamkcrgd004cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3JQxsZAMKCRgD004CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684802599; x=1687394599;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:references
         :mime-version:message-id:in-reply-to:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=f9G5O2/BZNmb0eHsnq2ATvSa36uhU4HNGz8hkRwg9Yw=;
        b=CpjZrhRUP2av4rhmekZWXcxrsy61gl+3XglFHWLNKSPuP2PKS4wljLv2pxBVRodiCa
         NCFMlZsukIQzUl0HRO8XGld1oUIcDaYckFdxIAgips/3lWO61N0/oYSx5WWA2fWX9J9z
         0RdbSCmdc9CqJ2OlMnVjOQZvmODzWedeUzgVB3330xUK1ndQwKFlEhBuCC7YHrhz9dGX
         j3PKUvlbybXTbLZy8fIrP1Wcc8Z3K4/hbJnG2h+I1GSk75ec+e5sxgPEWMay1/x+dYqu
         nMIptNcKFMQ0mD9UrN132evba5pwm9IflMb3Dw7u5n4ewNNgVP29rBMoa/PNDpjrtDAQ
         hnaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684802599; x=1687394599;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:references
         :mime-version:message-id:in-reply-to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=f9G5O2/BZNmb0eHsnq2ATvSa36uhU4HNGz8hkRwg9Yw=;
        b=aSV8l672L6+MzXB8HAP1qfMJhD8VVFS6AnI2o6xzb7YGw6XSzjJmUFqWHtaMFXbiYZ
         jTgxHwm+Ng4LPoL6BrKNLZz8x2OmbFcp66vbBT1LTxvClXnoIwgJxrBuEQOsb3UnVhc0
         WQNdLfZUfpZw4N5LgDgMVEYglMsToQM8afC+z9hijw2Cc9VQ04SAb48NH1FOnuGWyZaS
         9gXgh10Zx22xveMdehLNxlTayhnk/aew0Y0IGddZM6schnC0WfLFjOf3yATrd/yN1e/X
         7/O6mfywPWeMthixK4lj1E4+tMKoXcmQP1QKXYuriP9qviKipfvPmS4YEULb2aBloMj5
         QUIA==
X-Gm-Message-State: AC+VfDy2XFpqpmpQs5uxVXz6el5/Rza6Niz9k5V7/aM/C2xQlFLzxFEC
	6L/3LgeefAO29bzUzmCNMtA=
X-Google-Smtp-Source: ACHHUZ5RJOVoxqHWIamDp2SY9yJhm4af0LWT1Rp9NBTFTLkPKzid2H47hdg6KkncTO+OsFi0s+NOFw==
X-Received: by 2002:ad4:4e72:0:b0:623:63b8:d49e with SMTP id ec18-20020ad44e72000000b0062363b8d49emr2353529qvb.2.1684802599368;
        Mon, 22 May 2023 17:43:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:9a3:b0:623:8dca:c339 with SMTP id
 du3-20020a05621409a300b006238dcac339ls4881286qvb.1.-pod-prod-01-us; Mon, 22
 May 2023 17:43:18 -0700 (PDT)
X-Received: by 2002:a1f:c14a:0:b0:43f:c71d:f027 with SMTP id r71-20020a1fc14a000000b0043fc71df027mr3705251vkf.12.1684802598102;
        Mon, 22 May 2023 17:43:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684802598; cv=none;
        d=google.com; s=arc-20160816;
        b=lqzX5oYxIS4SFHpYGbc9tF0j5WiEiV7fH/jafftFYigG2JjI2yAUgxtzRwIlxO5oMP
         4avbqIjoU6vJ8Gnf4yy0ENzhKrBY+Ir4aSbQXCjWox9Oa5yS6Y9UzjzTtEhFljn7gphA
         qCk6iccqq4AHXAWCVnpk4sYb3lUGEE5fHigdtOgXPE7J1k4uhq1OJUU5KPIa2awo2j/f
         UPv0jPgcMoAvK0kbLmv333YEwbXrFLcjhkOWIMdN206buB707qOfQ1STgxOjX4fY/xl8
         uNIkF+2hOGMBZuesb/73LdzMv+gd8h0eUuwKyff/quqO9TVis5/xp+juBHQGtZZ7Tc05
         k+zQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:from:subject:references
         :mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=msTm3oYdeXIT0hSlyDwQQkvc5wY+Q8yhko13bmJatr8=;
        b=xhZGdIIHSBlXr0+tgxwdZk9y5CThuq0ngpYgDyGSAoBLix3RhdRqom+pm23LkKHIXC
         97F7G5K0gon7Gu13um6fxXl3up3dzxRG3d7xaQJEfYZ6uGrHGucxVMTr6GvxLx9Ioq2e
         qJlXccJXN0VmxOW/ln9dfo70bXjQUHJfqSCoSCJjL9hiToKmoZ+0SQqqZbUycFAyfdrZ
         +R/sbWdi4aKt58IJRudDnKvmM8khkkeQ7T2DYGmMmaRvJYpj6SmXURyy4ddoKLKmTX+q
         wJkIZlCgIdNjXHFR98UO+DOYEQgx2YVpTiyqR02GJ0NX/o+zL2Mxhja6RW4h3+nfbORt
         BOcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=GVCKc+6r;
       spf=pass (google.com: domain of 3jqxszamkcrgd004cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3JQxsZAMKCRgD004CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id 17-20020a0561220a1100b0043fc21a7c27si333151vkn.4.2023.05.22.17.43.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 May 2023 17:43:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3jqxszamkcrgd004cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-ba83a9779f3so13040647276.1
        for <kasan-dev@googlegroups.com>; Mon, 22 May 2023 17:43:18 -0700 (PDT)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:3d33:90fe:6f02:afdd])
 (user=pcc job=sendgmr) by 2002:a25:10d4:0:b0:ba8:181b:2558 with SMTP id
 203-20020a2510d4000000b00ba8181b2558mr7332911ybq.4.1684802597761; Mon, 22 May
 2023 17:43:17 -0700 (PDT)
Date: Mon, 22 May 2023 17:43:08 -0700
In-Reply-To: <20230523004312.1807357-1-pcc@google.com>
Message-Id: <20230523004312.1807357-2-pcc@google.com>
Mime-Version: 1.0
References: <20230523004312.1807357-1-pcc@google.com>
X-Mailer: git-send-email 2.40.1.698.g37aff9b760-goog
Subject: [PATCH v4 1/3] mm: Call arch_swap_restore() from do_swap_page()
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Peter Collingbourne <pcc@google.com>, 
	"=?UTF-8?q?Qun-wei=20Lin=20=28=E6=9E=97=E7=BE=A4=E5=B4=B4=29?=" <Qun-wei.Lin@mediatek.com>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	"surenb@google.com" <surenb@google.com>, "david@redhat.com" <david@redhat.com>, 
	"=?UTF-8?q?Chinwen=20Chang=20=28=E5=BC=B5=E9=8C=A6=E6=96=87=29?=" <chinwen.chang@mediatek.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	"=?UTF-8?q?Kuan-Ying=20Lee=20=28=E6=9D=8E=E5=86=A0=E7=A9=8E=29?=" <Kuan-Ying.Lee@mediatek.com>, 
	"=?UTF-8?q?Casper=20Li=20=28=E6=9D=8E=E4=B8=AD=E6=A6=AE=29?=" <casper.li@mediatek.com>, 
	"gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>, vincenzo.frascino@arm.com, 
	Alexandru Elisei <alexandru.elisei@arm.com>, will@kernel.org, eugenis@google.com, 
	Steven Price <steven.price@arm.com>, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=GVCKc+6r;       spf=pass
 (google.com: domain of 3jqxszamkcrgd004cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3JQxsZAMKCRgD004CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

Commit c145e0b47c77 ("mm: streamline COW logic in do_swap_page()") moved
the call to swap_free() before the call to set_pte_at(), which meant that
the MTE tags could end up being freed before set_pte_at() had a chance
to restore them. Fix it by adding a call to the arch_swap_restore() hook
before the call to swap_free().

Signed-off-by: Peter Collingbourne <pcc@google.com>
Link: https://linux-review.googlesource.com/id/I6470efa669e8bd2f841049b8c61=
020c510678965
Cc: <stable@vger.kernel.org> # 6.1
Fixes: c145e0b47c77 ("mm: streamline COW logic in do_swap_page()")
Reported-by: Qun-wei Lin (=E6=9E=97=E7=BE=A4=E5=B4=B4) <Qun-wei.Lin@mediate=
k.com>
Closes: https://lore.kernel.org/all/5050805753ac469e8d727c797c2218a9d780d43=
4.camel@mediatek.com/
Acked-by: David Hildenbrand <david@redhat.com>
Acked-by: "Huang, Ying" <ying.huang@intel.com>
Reviewed-by: Steven Price <steven.price@arm.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
---
v2:
- Call arch_swap_restore() directly instead of via arch_do_swap_page()

 mm/memory.c | 7 +++++++
 1 file changed, 7 insertions(+)

diff --git a/mm/memory.c b/mm/memory.c
index f69fbc251198..fc25764016b3 100644
--- a/mm/memory.c
+++ b/mm/memory.c
@@ -3932,6 +3932,13 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
 		}
 	}
=20
+	/*
+	 * Some architectures may have to restore extra metadata to the page
+	 * when reading from swap. This metadata may be indexed by swap entry
+	 * so this must be called before swap_free().
+	 */
+	arch_swap_restore(entry, folio);
+
 	/*
 	 * Remove the swap entry and conditionally try to free up the swapcache.
 	 * We're already holding a reference on the page but haven't mapped it
--=20
2.40.1.698.g37aff9b760-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20230523004312.1807357-2-pcc%40google.com.
