Return-Path: <kasan-dev+bncBCF5XGNWYQBRBCGTYSOAMGQEI4W62PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id D583264658E
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Dec 2022 01:02:17 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id cj6-20020a05622a258600b003a519d02f59sf38961157qtb.5
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Dec 2022 16:02:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670457736; cv=pass;
        d=google.com; s=arc-20160816;
        b=dfJoouB9Eq8m60DRjHEyVHV2obMtk8v2sOUqjnugEUTud3OZKmxQsBNj3govAwJjVn
         WsERl/06t5V/csrzFdOPhbGiDugpwZ8N0MKtlZ5u1wOhuJ6kEO8J6za7QETiLv/vDLFG
         TDL9WqHYwOQ08GaCnk0iwN0+FrIZOVTh1J7bEl7WzqUUTXpL/TAvndPYfLA6EWrsrBmn
         LCIa4o3TYgNZ4xrKodcAH/TVbL0ywVR+3S5czMCH1tC0BvnAwDYYTVDnT6h9dQZsaR9e
         9q+sc5dsNZtOUVzbLugnTBdGRS6uhtbdiUGa4L2p/VpC9V5ZFg91xqoLsEeR7XHqc0p7
         8tlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ch5yr7u0NZFWwi0PnuI8Ug8uymRX8tIY8ikJCiV22NI=;
        b=0Tgqb3+Y72R9zesUypgclEhVftnZ+TFxurBrixcUus+v9lcVIKoILjoMG6TS9fQsmy
         275MwXStiS2zBc1LULlXttcSyymBDHH/E9K3/pjBzZhPh5MfPXao/14onkBbdKuGOBZF
         EtZhPPbWCqltKhlnhOxJDtzFWCD7mbuLcAcWl2o7gVwTdSSi/kVfyc5eTFkNG4cFLduX
         MrCAESdqfxmkupYc4IxVvlbnI05uFIAcBKaaQZrT3t5iDam/gQ6aLX+ZtJbiXy/oq7Lx
         Q+GPzl1jXZBxxIBz3qG0uLHKGbTm1jGmymVZYfMSED0cukQbOQFHPAKmHCKTxxHJpZUn
         4X3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=CfAuGzp9;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ch5yr7u0NZFWwi0PnuI8Ug8uymRX8tIY8ikJCiV22NI=;
        b=aASBf79MJdiJIqmhuj62fv81+WEtxU93n7JG0v5KVHmM6AilRgh/eEQjRyh1hWHDNm
         VS9fSQ7oOsTAsiB2MBTmj2vtlhkYXKMXe89iNThq6pr+CYPBzuUJDPJCv1yw4g3GjCw7
         8X5hgEjKAclg8k6N+KrpFldlTPQ7rZtVBOsLWGm1O+F/dRh0bbagRxPoejPddQ7L5W2H
         uNzEL68z112xLBp4VtZxoX7ky5nrWQinVRG9Hc0RJAxj8exa0xY00h9p5ewYPzVIvko3
         N7Ta7LePzy9t5z1tQUotjOnHTs65wfEueVXvV9Dvr53qvHKFU9xSIo2tZwyMEkU8ThaL
         WjGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=ch5yr7u0NZFWwi0PnuI8Ug8uymRX8tIY8ikJCiV22NI=;
        b=Mpv/PEybPa8bhbWbBsEQPnlMplOooYYzfqnMQSAsznz3FALKDiesznEHPgOyESnUoa
         25rvuCmrnd+baNsfzWB3My/f2DRLaMOHzWSibUvKJ7dFIqOI+MmO7A7jzrluIL7SuuGA
         a8ffe+4iePUyAQZzjd27mZjsYEJZ5ygHhkl54Nb2uDOL2um9oiUIbhD3Ex34pp0qNrRa
         jxbyVVCPU5LZ7hNlaW6Igr+yyy6vakAikfCU7gk3+M5BoUOM/2prldKP2gPUiFVgEth4
         vVlZ/marwIJ2kSNzv6VHG0n2I5JVGG2wBRgcGHftu5rBbymbx0pFhmOo07XXLMPpW+h9
         1baA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pk5B2RFq+0EPG51D9FYJ9EXTsBwJv8/WOcf7bLq830QSC5M6apO
	Ffu0n7/b60DCTAY+IBpDjGM=
X-Google-Smtp-Source: AA0mqf61QOW3CoAVldos2lwe4ijmaqxo6EXtCiKjOZoFch5woOAe7NcKfAzcLc9qz2tiW2QILdzwSw==
X-Received: by 2002:ac8:5355:0:b0:3a5:4074:4753 with SMTP id d21-20020ac85355000000b003a540744753mr66531856qto.605.1670457736680;
        Wed, 07 Dec 2022 16:02:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:43cc:0:b0:3a5:4442:58e3 with SMTP id w12-20020ac843cc000000b003a5444258e3ls2228142qtn.7.-pod-prod-gmail;
 Wed, 07 Dec 2022 16:02:16 -0800 (PST)
X-Received: by 2002:a05:622a:905:b0:3a6:8af7:dccd with SMTP id bx5-20020a05622a090500b003a68af7dccdmr32257820qtb.406.1670457736079;
        Wed, 07 Dec 2022 16:02:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670457736; cv=none;
        d=google.com; s=arc-20160816;
        b=vNwMSxfzgvpSAiUyZI2giPQsXPalz2FrzI1GY+NJSLu0cz2X9Bc2i7G5dFZ9bblgs4
         pFlmbVY9XcXElf4ppFbllqAPbGgVBh7a6RQ8FAOB0/3VSokUde1mv5TNsxX/4KpHp//i
         ygR59HtSugSCxwfKBxsx3Ir6+nKriWOUnFPnNMHH6jXiwKIOGMk6j6oAZt/7wzj4pjFz
         uYbdGArG0TFrExeohZ2oc1SIpye7WPLCfm7igIjMSW1dG7wUXbOr2msG6PmJM4Q8zhfU
         ZEAJ5r+UQZsbbrs/y9nfmZ0NhFSNV5YWcfer8BUDva4mFh02BYGY2NI/aNw0w4QSYTMd
         F1Zg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=dk1yAoyQU+RLCYzQPhP3++n5k0AlqyyhOlwfArVtCN8=;
        b=Q5xPaogE4E+xYaleqBWsBIIE+VSQ04Br2M87PIb4rIbQO9b4oBQvyLhtfdhuZ103j+
         4id3tMnUeKmsejFG7dxwBf3O8ryRBXaMXaqS9oCZvMEbM3kOzfAnxciZyJfACp3DB/+I
         XC86Lji9oZ3v9OjT9PGnRi6F0VmHlmlmV3s8+rbvhB1BivQLusXg62rX4JXiYwm8QvIZ
         2TC9720o2aRf2X8Bhvh3GqH6he4DB/omLmivi+UQruw5DZY+/tR5Yf4Bu3rNn/40LRD0
         BXtpRwtYhQ0Wil7mnls5Zk7y2s56ts3qBY+8LbLQgzABS33uJJKicAI2Fjn6ErafZxWo
         soHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=CfAuGzp9;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id z20-20020a05620a08d400b006fbac5a9709si1085345qkz.3.2022.12.07.16.02.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Dec 2022 16:02:16 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id k88-20020a17090a4ce100b00219d0b857bcso3302224pjh.1
        for <kasan-dev@googlegroups.com>; Wed, 07 Dec 2022 16:02:16 -0800 (PST)
X-Received: by 2002:a17:90b:711:b0:210:9858:2b2c with SMTP id s17-20020a17090b071100b0021098582b2cmr102785702pjz.191.1670457735590;
        Wed, 07 Dec 2022 16:02:15 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id s30-20020a63925e000000b00477def759cbsm5933519pgn.58.2022.12.07.16.02.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Dec 2022 16:02:15 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Jakub Kicinski <kuba@kernel.org>
Cc: Kees Cook <keescook@chromium.org>,
	syzbot+fda18eaa8c12534ccb3b@syzkaller.appspotmail.com,
	Eric Dumazet <edumazet@google.com>,
	"David S. Miller" <davem@davemloft.net>,
	Paolo Abeni <pabeni@redhat.com>,
	Pavel Begunkov <asml.silence@gmail.com>,
	pepsipu <soopthegoop@gmail.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Andrii Nakryiko <andrii@kernel.org>,
	ast@kernel.org,
	bpf <bpf@vger.kernel.org>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Hao Luo <haoluo@google.com>,
	Jesper Dangaard Brouer <hawk@kernel.org>,
	John Fastabend <john.fastabend@gmail.com>,
	jolsa@kernel.org,
	KP Singh <kpsingh@kernel.org>,
	martin.lau@linux.dev,
	Stanislav Fomichev <sdf@google.com>,
	song@kernel.org,
	Yonghong Song <yhs@fb.com>,
	netdev@vger.kernel.org,
	LKML <linux-kernel@vger.kernel.org>,
	Rasesh Mody <rmody@marvell.com>,
	Ariel Elior <aelior@marvell.com>,
	Manish Chopra <manishc@marvell.com>,
	Menglong Dong <imagedong@tencent.com>,
	David Ahern <dsahern@kernel.org>,
	Richard Gobert <richardbgobert@gmail.com>,
	David Rientjes <rientjes@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	GR-Linux-NIC-Dev@marvell.com,
	linux-hardening@vger.kernel.org
Subject: [PATCH net-next v2] skbuff: Introduce slab_build_skb()
Date: Wed,  7 Dec 2022 16:02:13 -0800
Message-Id: <20221208000209.gonna.368-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=6532; h=from:subject:message-id; bh=I5zpjdf6giyPTGWK3waT0b1aZ9hEwojgcygujraz8dc=; b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBjkSmEkOgkOZcWwciYH5GLWV3obftsCrvUcG4e847b Bi5nkbGJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCY5EphAAKCRCJcvTf3G3AJrfZD/ 9J2X/Gw9ncWI4dk8wA/WdzHwO05CFaHzRpUpXr+GMG8xWhch5i+SxqJDXVTzXb0YA7TXlpkO9D+otk 5R29AmizYM7EXsl1yZeyMbGQ5hpAufcuX82qAOIodz/lW3bzrzs21vRcUZLrwoV/Fyw0pxzHY5Pf5h ph+jxiId3DghZjSkowXYtsPGXEcnWxRVtUdTcXIwi4Ry8XvyJpqk0jOBV7ZnM8kEJVJ6pUgNjdt61c Gdhjag0bgthVFgM2mpz/QmavD+S+3QlwLB9a3DoVWUJOKJTSQrHNNzbygYMoN5RqmnPz+OcqVneI4E +XcJ6Dh3/v1qbD+rVNET9u/b3bPLy/x06rWB8dgrKn0P/mb601uzlKCKhmm1TG24z1Z9h8w366AVA7 9dU9EwQINOJTDi6NUYcnGa3GApoKuVGCZ03C9xewFJ6BfCrj5qjwQT7CGTH5Vug9puDgl7rBqlIskS WiKGOdtd2hO+BdD3ggipo0i6+bmO07sYVTvcUDv/6GsZZyUy8jET1YpxQS6KU6pKyabXunytY0XNDN o2/3jZeX+Q1xeLy+ge8aeZvS6ypBvKHk51BiHlDd+HM/Ea0wvyjuZr6d5xnNwg9UqO3Po4lIYkKctJ kXJR6WE6EASTgDFD1Xdp19J2MB65NyB2AMFRRTo2I8Nk6cmA+N6Z+5R+M5Sg==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=CfAuGzp9;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1029
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Content-Type: text/plain; charset="UTF-8"
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

syzkaller reported:

  BUG: KASAN: slab-out-of-bounds in __build_skb_around+0x235/0x340 net/core/skbuff.c:294
  Write of size 32 at addr ffff88802aa172c0 by task syz-executor413/5295

For bpf_prog_test_run_skb(), which uses a kmalloc()ed buffer passed to
build_skb().

When build_skb() is passed a frag_size of 0, it means the buffer came
from kmalloc. In these cases, ksize() is used to find its actual size,
but since the allocation may not have been made to that size, actually
perform the krealloc() call so that all the associated buffer size
checking will be correctly notified. Split this logic out into a new
interface, slab_build_skb(), but leave the original 0 checking for now
to catch any stragglers.

Reported-by: syzbot+fda18eaa8c12534ccb3b@syzkaller.appspotmail.com
Link: https://groups.google.com/g/syzkaller-bugs/c/UnIKxTtU5-0/m/-wbXinkgAQAJ
Fixes: 38931d8989b5 ("mm: Make ksize() a reporting-only function")
Cc: Jakub Kicinski <kuba@kernel.org>
Cc: Eric Dumazet <edumazet@google.com>
Cc: "David S. Miller" <davem@davemloft.net>
Cc: Paolo Abeni <pabeni@redhat.com>
Cc: Pavel Begunkov <asml.silence@gmail.com>
Cc: pepsipu <soopthegoop@gmail.com>
Cc: syzbot+fda18eaa8c12534ccb3b@syzkaller.appspotmail.com
Cc: Vlastimil Babka <vbabka@suse.cz>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Cc: Andrii Nakryiko <andrii@kernel.org>
Cc: ast@kernel.org
Cc: bpf <bpf@vger.kernel.org>
Cc: Daniel Borkmann <daniel@iogearbox.net>
Cc: Hao Luo <haoluo@google.com>
Cc: Jesper Dangaard Brouer <hawk@kernel.org>
Cc: John Fastabend <john.fastabend@gmail.com>
Cc: jolsa@kernel.org
Cc: KP Singh <kpsingh@kernel.org>
Cc: martin.lau@linux.dev
Cc: Stanislav Fomichev <sdf@google.com>
Cc: song@kernel.org
Cc: Yonghong Song <yhs@fb.com>
Cc: netdev@vger.kernel.org
Cc: LKML <linux-kernel@vger.kernel.org>
Signed-off-by: Kees Cook <keescook@chromium.org>
---
Is this what you had in mind for this kind of change?
v2: introduce separate helper (kuba)
v1: https://lore.kernel.org/netdev/20221206231659.never.929-kees@kernel.org/
---
 drivers/net/ethernet/broadcom/bnx2.c      |  2 +-
 drivers/net/ethernet/qlogic/qed/qed_ll2.c |  2 +-
 include/linux/skbuff.h                    |  1 +
 net/bpf/test_run.c                        |  2 +-
 net/core/skbuff.c                         | 52 +++++++++++++++++++++--
 5 files changed, 52 insertions(+), 7 deletions(-)

diff --git a/drivers/net/ethernet/broadcom/bnx2.c b/drivers/net/ethernet/broadcom/bnx2.c
index fec57f1982c8..b2230a4a2086 100644
--- a/drivers/net/ethernet/broadcom/bnx2.c
+++ b/drivers/net/ethernet/broadcom/bnx2.c
@@ -3045,7 +3045,7 @@ bnx2_rx_skb(struct bnx2 *bp, struct bnx2_rx_ring_info *rxr, u8 *data,
 
 	dma_unmap_single(&bp->pdev->dev, dma_addr, bp->rx_buf_use_size,
 			 DMA_FROM_DEVICE);
-	skb = build_skb(data, 0);
+	skb = slab_build_skb(data);
 	if (!skb) {
 		kfree(data);
 		goto error;
diff --git a/drivers/net/ethernet/qlogic/qed/qed_ll2.c b/drivers/net/ethernet/qlogic/qed/qed_ll2.c
index ed274f033626..e5116a86cfbc 100644
--- a/drivers/net/ethernet/qlogic/qed/qed_ll2.c
+++ b/drivers/net/ethernet/qlogic/qed/qed_ll2.c
@@ -200,7 +200,7 @@ static void qed_ll2b_complete_rx_packet(void *cxt,
 	dma_unmap_single(&cdev->pdev->dev, buffer->phys_addr,
 			 cdev->ll2->rx_size, DMA_FROM_DEVICE);
 
-	skb = build_skb(buffer->data, 0);
+	skb = slab_build_skb(buffer->data);
 	if (!skb) {
 		DP_INFO(cdev, "Failed to build SKB\n");
 		kfree(buffer->data);
diff --git a/include/linux/skbuff.h b/include/linux/skbuff.h
index 7be5bb4c94b6..0b391b635430 100644
--- a/include/linux/skbuff.h
+++ b/include/linux/skbuff.h
@@ -1253,6 +1253,7 @@ struct sk_buff *build_skb_around(struct sk_buff *skb,
 void skb_attempt_defer_free(struct sk_buff *skb);
 
 struct sk_buff *napi_build_skb(void *data, unsigned int frag_size);
+struct sk_buff *slab_build_skb(void *data);
 
 /**
  * alloc_skb - allocate a network buffer
diff --git a/net/bpf/test_run.c b/net/bpf/test_run.c
index 13d578ce2a09..611b1f4082cf 100644
--- a/net/bpf/test_run.c
+++ b/net/bpf/test_run.c
@@ -1130,7 +1130,7 @@ int bpf_prog_test_run_skb(struct bpf_prog *prog, const union bpf_attr *kattr,
 	}
 	sock_init_data(NULL, sk);
 
-	skb = build_skb(data, 0);
+	skb = slab_build_skb(data);
 	if (!skb) {
 		kfree(data);
 		kfree(ctx);
diff --git a/net/core/skbuff.c b/net/core/skbuff.c
index 1d9719e72f9d..2bff6af6a777 100644
--- a/net/core/skbuff.c
+++ b/net/core/skbuff.c
@@ -269,12 +269,10 @@ static struct sk_buff *napi_skb_cache_get(void)
 	return skb;
 }
 
-/* Caller must provide SKB that is memset cleared */
-static void __build_skb_around(struct sk_buff *skb, void *data,
-			       unsigned int frag_size)
+static inline void __finalize_skb_around(struct sk_buff *skb, void *data,
+					 unsigned int size)
 {
 	struct skb_shared_info *shinfo;
-	unsigned int size = frag_size ? : ksize(data);
 
 	size -= SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
 
@@ -296,6 +294,52 @@ static void __build_skb_around(struct sk_buff *skb, void *data,
 	skb_set_kcov_handle(skb, kcov_common_handle());
 }
 
+static inline void __slab_build_skb(struct sk_buff *skb, void *data,
+				    unsigned int *size)
+{
+	void *resized;
+
+	*size = ksize(data);
+	/* krealloc() will immediate return "data" when
+	 * "ksize(data)" is requested: it is the existing upper
+	 * bounds. As a result, GFP_ATOMIC will be ignored.
+	 */
+	resized = krealloc(data, *size, GFP_ATOMIC);
+	WARN_ON_ONCE(resized != data);
+}
+
+struct sk_buff *slab_build_skb(void *data)
+{
+	struct sk_buff *skb;
+	unsigned int size;
+
+	skb = kmem_cache_alloc(skbuff_head_cache, GFP_ATOMIC);
+	if (unlikely(!skb))
+		return NULL;
+
+	memset(skb, 0, offsetof(struct sk_buff, tail));
+	__slab_build_skb(skb, data, &size);
+	__finalize_skb_around(skb, data, size);
+
+	return skb;
+}
+EXPORT_SYMBOL(slab_build_skb);
+
+/* Caller must provide SKB that is memset cleared */
+static void __build_skb_around(struct sk_buff *skb, void *data,
+			       unsigned int frag_size)
+{
+	unsigned int size = frag_size;
+
+	/* When frag_size == 0, the buffer came from kmalloc, so we
+	 * must find its true allocation size (and grow it to match).
+	 */
+	if (WARN_ONCE(size == 0, "Use slab_build_skb() instead"))
+		__slab_build_skb(skb, data, &size);
+
+	__finalize_skb_around(skb, data, size);
+}
+
 /**
  * __build_skb - build a network buffer
  * @data: data buffer provided by caller
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221208000209.gonna.368-kees%40kernel.org.
