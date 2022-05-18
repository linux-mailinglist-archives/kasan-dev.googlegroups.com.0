Return-Path: <kasan-dev+bncBCT7TQ7X2QEBBKPSSWKAMGQEVUC3IUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93e.google.com (mail-ua1-x93e.google.com [IPv6:2607:f8b0:4864:20::93e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7742852C6AA
	for <lists+kasan-dev@lfdr.de>; Thu, 19 May 2022 00:54:34 +0200 (CEST)
Received: by mail-ua1-x93e.google.com with SMTP id y15-20020ab0638f000000b00368a2d9b075sf1632844uao.13
        for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 15:54:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652914473; cv=pass;
        d=google.com; s=arc-20160816;
        b=XNO2mNKqcRJHjMlLGtvMNHXdioL1EPc82t2bRDhsL/TjOXvx8MxSe21IGmzfNUJJPn
         GPSx03fMDd596JQktFDPfE03451Xug7FqPF5g2+lA9mlML4yVE0TmB4VUHxG9ofPPDo+
         xWhwmhWodkIxrVbpwAQFUtBVizKm84FUEsJ18SotnjYPKpUZTFZwGZ2yu2/L6XSvJA78
         +CF2ihoBWSxoVfLiTqeTnZbqzyClQjdThWx4kv2ui6yI7SprSxNFkTqF/7rOSCVrBCB2
         Ov8jFeMdrnBIDrYcdjCOwbB2UCdVr2RVQ49+T6dZNgC5a7S1Tqooft4soW/AOQe9iL8h
         1/Zw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :reply-to:mime-version:sender:dkim-signature:dkim-signature;
        bh=eR9EADT/qw5CMoZQtUq3c+3xVUpmbdDjSaw5YPzIm9s=;
        b=jMQXvMBi0BYnFPk5ZnypgnKyh3qY/hmcToX1pftIM59ApGGNj5mkig+NPDD4J2xhad
         qCMWoX+1WtMeh4+M7789C2vt5ObkyAtWyuDx8CBVYcSRoTHJ39X/tv3eJVlscRyshHkD
         RUSM/nDfq+qaZ70uHtCAo8vSd/H4poLq9B2vnDfsz+T5vR+Okrp+fTZwHHR28BPhurjw
         ga+DSWGWZ0D82xA+T0Rtsqbr3NXsZ/B3cTt/Leape6X9D1z3ikUpg/Nc2LoamNZXYD+Z
         aYlm7E9h1fglPxw4sbPbO5ye0R+l55YW2n4AOAoST7gLqJ3hcXGRDMX3h7CVZqa8apP2
         avRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Q5PFiuq+;
       spf=pass (google.com: domain of weboutloock4@gmail.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=weboutloock4@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eR9EADT/qw5CMoZQtUq3c+3xVUpmbdDjSaw5YPzIm9s=;
        b=YbkcaoFqkY0igudE7X+MCw4eZqKSk59tapMWpGDwv3QZCzQ727H0DXIvI+Ycave+Vc
         xefRannNaTg7XVAhX9qdy67prkC/PbLYE7MIk0oT9cktPScslISlJKfIpo+lDKKbZv9D
         46z404j4J0kTDzq+sG63gE00V7ayJlZYxrAHcZiQrQSXy31sCYnJQGEjM/s8R91V5o8u
         yvSy68ZS4qaJuwhvJueLbzqLMCJubVmm2fDV492kk31XeftMPJxHQlJ/y5VAGXtnnHYv
         IOPGqJGGkGWjHZCH5w9wF7mQSHiKy0wlH/5f8ZXohzNjD/rEeOMhJuT07XxjylhUVHZm
         F3+Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eR9EADT/qw5CMoZQtUq3c+3xVUpmbdDjSaw5YPzIm9s=;
        b=ZZnHXr0dNdW4PNuWRzfOSS5qHUBpW60dV+r0yyKm2pinP398c8IC6kcU4mWVupXzkW
         bnt1h7KJp43Hxqsn8amNC0ck4wAfLmRQ0WTky0DfTLBv3u1Eph5BYccYvwTpREM1ZgSp
         Wh+xyCcNIERObFa/SXbSfOO/KVK+ut4qrWItR/JI4rzboF0ubndx02k28hatbWOemolU
         5ELt+pCMkFPb9FPS8NY32YjTjDlas+WBsAEFWAS1fv5hbnyLB14IPbX0OwkkDmLHL8jC
         k59Tr52FUwLpTL8zDS/OrBQBXbVpwr0psqLYuoLbS9UpMKCrJrizQkY0/NpfV9qezWhi
         X5WA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:reply-to:from:date
         :message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eR9EADT/qw5CMoZQtUq3c+3xVUpmbdDjSaw5YPzIm9s=;
        b=DV6vz247YZ4psIWx58ZbsDALiFlBKPldn+VAD7mtZWc+cz9EmQACO7v0GmJUlBaScU
         cZKPHZpVBCa3CTQdKjIEIEE/64zYD/8USVHG7SEdS43hlSlmcz8s5GzpJ6nEBVj9FaxH
         ItrDFrex+CYHvXXweO0wZWEzEIxO9OgyXcA7toeZO1rdwnuovtv3RzT1Kav+Fq4SVzrk
         hkc8T0LTXa+4/1WnswlILM96ix5Wc3+w4Aj8cWo8QjvqslpXaP+D1xcO33G3gtLDEfVP
         k4Jf+SwxEaQ5ZK2Hfnu8OeE6xe0wpQxr8vLfv2oPB+RS37UzhuUdIMjokHihDV4+Brs1
         XeOA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533UbnlRa7gEB12ERONMhT+NscporaNZWGJK/wOlUuXcij3vIdUh
	j2UxYdAGzD7ksJaTHlhefh0=
X-Google-Smtp-Source: ABdhPJyii4zgE2fFGYnaPZuBnELD68nFEkEAi65kyKSSk6o2q8RxpLEP0SXQIbkD5IhHWE0iF5zBBQ==
X-Received: by 2002:a67:c40c:0:b0:32c:e5d2:8b50 with SMTP id c12-20020a67c40c000000b0032ce5d28b50mr926004vsk.6.1652914473303;
        Wed, 18 May 2022 15:54:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:3e88:b0:32a:5224:afa0 with SMTP id
 m8-20020a0561023e8800b0032a5224afa0ls241423vsv.3.gmail; Wed, 18 May 2022
 15:54:32 -0700 (PDT)
X-Received: by 2002:a05:6102:1519:b0:32d:8834:f17a with SMTP id f25-20020a056102151900b0032d8834f17amr868336vsv.1.1652914472802;
        Wed, 18 May 2022 15:54:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652914472; cv=none;
        d=google.com; s=arc-20160816;
        b=JnjcQYPMgs7TCXHwPvoNZIwz8xcIKsI2Is6DwPBZ+h9Mpsr36HXBAt6wcgku+orqVE
         E/dGletm6B+wGYlEaEfSrO7/puRzZ9za+IS991UPEb17k7vMvGDsfLuzIAOACqLxznEy
         WkpIbl+yltPxnByxFlJpC1uC1Z9QH8jY5DeANICuVBsJppWJyTKN4htPQb2coq++9DUz
         /Jl823vTfHAV94tVZGXA4WYWClp3x/J8A1dKgu3IwZWMeADG9oIrbYVZ+BL17wGufmzo
         IFzpN5ZXjBQhNqACSrLp71Ptot4HBjtGuHJ441aGFWouvyxpoxGj0z9HUSONTlfQ8A/d
         qT5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:reply-to:mime-version
         :dkim-signature;
        bh=mZ3wqB4NmL7z6lpFr/h15h1rYqsZKafJnUpMVahbEPg=;
        b=fooLXukVvrjUG2862uxQHjPIDue+R6VMLcl1cK1A0uw0A0Q7i/gQifJez/cAYTESps
         +nqry5uK+cGai5AqQeQl88BlyHK9XFbbMpgdW70aWSfDaaPSZ5pH65vV8KXCLHy5D7ya
         u2yotzBb/SFOmhTFbUXIvYZZn6lwswhZTa620gXtZ1YmPEoOBarA1pCab3LnxCz1lKtF
         7FL150r1JxvBtlRufJ5w/A5+Gqk6lJ0jVXo8ZoXzLyK1wcfqezzGUwSLTuFbldx55MfM
         PAJ+DhyeBnJy7bHFnrO7MN10JbQvh+7ZlQrs02kIPFHUoT/mlGnGvf/Ihmzxz5qBFbJy
         91pw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Q5PFiuq+;
       spf=pass (google.com: domain of weboutloock4@gmail.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=weboutloock4@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-yb1-xb31.google.com (mail-yb1-xb31.google.com. [2607:f8b0:4864:20::b31])
        by gmr-mx.google.com with ESMTPS id 40-20020a05612216a800b00357324ba38csi9736vkl.5.2022.05.18.15.54.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 May 2022 15:54:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of weboutloock4@gmail.com designates 2607:f8b0:4864:20::b31 as permitted sender) client-ip=2607:f8b0:4864:20::b31;
Received: by mail-yb1-xb31.google.com with SMTP id r1so6125122ybo.7
        for <kasan-dev@googlegroups.com>; Wed, 18 May 2022 15:54:32 -0700 (PDT)
X-Received: by 2002:a25:8244:0:b0:64d:c355:4b75 with SMTP id
 d4-20020a258244000000b0064dc3554b75mr1829378ybn.386.1652914472521; Wed, 18
 May 2022 15:54:32 -0700 (PDT)
MIME-Version: 1.0
Received: by 2002:a05:7000:7143:0:0:0:0 with HTTP; Wed, 18 May 2022 15:54:32
 -0700 (PDT)
Reply-To: tonywenn@asia.com
From: Tony Wen <weboutloock4@gmail.com>
Date: Thu, 19 May 2022 06:54:32 +0800
Message-ID: <CAE2_YrArF4Y02jp+OWHOBjctzPSCrOgfSuCxfozjjEXD+BUi8g@mail.gmail.com>
Subject: engage
To: undisclosed-recipients:;
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: weboutloock4@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Q5PFiuq+;       spf=pass
 (google.com: domain of weboutloock4@gmail.com designates 2607:f8b0:4864:20::b31
 as permitted sender) smtp.mailfrom=weboutloock4@gmail.com;       dmarc=pass
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

Can I engage your services?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAE2_YrArF4Y02jp%2BOWHOBjctzPSCrOgfSuCxfozjjEXD%2BBUi8g%40mail.gmail.com.
