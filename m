Return-Path: <kasan-dev+bncBDM2ZIVFZQPBBXOCZPCAMGQEKEUFXZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 02823B1BFBA
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Aug 2025 07:00:15 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-55b9b4d9ad2sf1140331e87.2
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Aug 2025 22:00:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754456415; cv=pass;
        d=google.com; s=arc-20240605;
        b=Se00kAMNMsUb+wCF7Ujc/lKprwQS+KHnceV4f2qkrB21BYzb+P4u/aqYXPMdTJn7+I
         1dCqrBKcYHWpXwJQdJhLRXAz/YEpYVYtWP+BmNR9htXhoPPXP/cZbR1oMwyyEMykaSJ9
         z55577Eq8AEyQnDTD12dSwbXr/WunTBxtMX7VuhRdLn0S3VHXQZmN+yx91LS77aeRwJn
         UrICfgLqjIpLJrF5+fdia7hM4fkumA29f8z69BOxYhxXVK51/CQGBz+M2DpOsUf8fAig
         ASPiJumz+6KNPdrcoPChpAdbtIZxvXaGN9Z5N79pBIaR0TM60rzW3a50O/7kIocsi5f6
         lB8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=g3gKqIVmtxb6NJVGmzRWrCxxzLO9RvB8KpnCu9fWYm8=;
        fh=GvlEFiJI2rzFvg1HS1RDAui9mvph+gu79/D3+S1vgV8=;
        b=HgZr2LH8N+0Vz0uMF+FjRrZdn9FfgvRRn6RAbawna+QQlh0v1tyQ3dGRC1Idv7cPF3
         foHVFWX7Ia9O1adB59XJDrdhMfqGz3JznkDctZgx43aGTBDmNMtEQXToNItTo7pVr3xs
         TUhEf/fWMtosnQUKSd+oL4w/WyJGyXonTOG91MxIV2j4DB+DNF1ysyFUMbYv4Lu1BVne
         hwixq4MK2yBX4+R7k3wprmYBjvOO5LsEhr+49hNaS1TMidgY85dYRdzP2PfzlnmF1bYR
         qzxY/dg2kDhu+XEVbKbblPbkpxMVOd34FPf9wdQm0A0RzGUHrlbGS2Q3hr31uABLUhSc
         1N0Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Mf15Wc3f;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::635 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754456415; x=1755061215; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=g3gKqIVmtxb6NJVGmzRWrCxxzLO9RvB8KpnCu9fWYm8=;
        b=VdJQMQM8C8X7HWr/3e4xU8TbHOCY8qIWMqvcLpQUjIqgeiPiTgLOy9ZESPchxL5tRl
         oaqTa2ID3lOntON4q0iA01jqvcE7aYJ2x59SuOjKTnVrR5CTOOy/Odo62VVhNi81axg0
         Zw4E07ISXQn2jSrYjJLuM1IcReGjRcWLp16T268PDg7LWPdnWU2hXLsGHTo7lAyN6Fz2
         YgBIFbXOEAi538lPs4a0h1R0KwSXZGLmULv3tCnQhoI/zXSdk+f+QbMHOX5wZAFdVWDs
         +HSl7RbpwyHonputGh/5ot+46P+1os1wioclUYGnuSmr00FL2woT+RYBOYALYW8VwURy
         hQvg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754456415; x=1755061215; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=g3gKqIVmtxb6NJVGmzRWrCxxzLO9RvB8KpnCu9fWYm8=;
        b=fR3CL3dDRGiUt6ARlXDfJ/2x+hjsjFUPRxrJynNWJVrVa6zuro8IEzBJxtKp0Z2RyH
         lfxoKGrXyx0SEfbX/ZwvRmJjqPQsrBMPTFQnSum7SRCpvcFpOCo6zRNLMMF4nZ8ZGqgI
         DiGl2X7aBkV6zoufxgUi4kUn33nEGgGqTgLKf7CkCvy08fV+8rFWQ0+rExO1gDBBgr85
         n5TQ6MXRaTvbNHn9fAG4VF67aQ63TakE7JwyStsI8qa4hSo57EFNWJMpSUjJ+o217SRm
         bnfXMDUV+7eiDcMHt2IIa4pDnKaFAeShNtpQ1twuDWJjkHrI/j5SZs0gMBP7IWbN4fZO
         CwJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754456415; x=1755061215;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=g3gKqIVmtxb6NJVGmzRWrCxxzLO9RvB8KpnCu9fWYm8=;
        b=vbJZVE987OYpjh4nIa9gne/JJSpMxb9t/D1Iixh3JXLvQi4TmLdzRIK6uJzqUIi8fm
         l3jtWxFqNdzV6DoZnIg2X4Sva52ofUA5fuuGWmoJWN1VLJeTMjY20owbz4oJfiXFKmbw
         TUe8A5H5JeR8gpawvz4isScE1KlngLVAGl+0opRKMHA0RQVXHagInPcdMGXAS8e/PffE
         wxk/xCJtB/eLNtQ1gOAL0vZroNs3C+IKxgJSm775sh+wxKHSeRwC63fL5PM3IpVMNyIz
         I4W625SNsPG6dpMpq2e5Ik0/bQtxrRElrWanMkhAqzldVIkQzcN10fd4nX4mT8U5pZJI
         QjyQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWICKCx7HEZ18vTm1x2oJDfGXs6uhwRugsuFFL31XYkT9rOzuIHdhIUZMiS+m9PL8szYNpg+A==@lfdr.de
X-Gm-Message-State: AOJu0Yw4O0AEQfj3jbkY3PgYhkfHZy6MCpPK2z/2BpfDDKqu8AExwWTp
	6whHYMsqqSwmlr9r48VjSkAxC0Ey+Z1nrwNu4Q7/9iRtUF9xtGGN2RCW
X-Google-Smtp-Source: AGHT+IFt2tYuw/2uajI9ybbrFGe5W2OvCbqAe/fdBJU/o75PAVfbYVwbTyPbdtOieoheXKWnFRhaJw==
X-Received: by 2002:a05:6512:224d:b0:55b:91b6:4473 with SMTP id 2adb3069b0e04-55caf2cdc07mr410163e87.9.1754456414176;
        Tue, 05 Aug 2025 22:00:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf+aNA8wFwyeo2BDhHXyDYVLlq2Bi+vHmYoeRf9iQNRhg==
Received: by 2002:a2e:b549:0:b0:332:347f:54ec with SMTP id 38308e7fff4ca-332381981e7ls11566041fa.0.-pod-prod-06-eu;
 Tue, 05 Aug 2025 22:00:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXik7J0mYmVDs2xOYOpjXk2rwQtx4MyPzwk8zI2F1APl0Fkm4zv5dLjaicFdchzWJE5Z2kgfBi84G0=@googlegroups.com
X-Received: by 2002:a05:6512:3c88:b0:55b:838c:d900 with SMTP id 2adb3069b0e04-55caf2f43aamr350839e87.19.1754456410949;
        Tue, 05 Aug 2025 22:00:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754456410; cv=none;
        d=google.com; s=arc-20240605;
        b=DBR8XlY0OSIvIUJTs6h86A47+n11JX+R/ESabL+Pb8QH+qrdMIsLd8wnjqYbgwhL/H
         fO1B+XY/Ay/VjLWDmBUzIOeIUJt9ZLrHuQmYGdJQ5r2jahADFBl36KbslmlfWymPJe7m
         M/cQtlvmJpo1SoZo3tzHhrSxlJgmaZWSL+UcUC1xS+ymeGdTiBTMGvKRWtTHWK1GEO4P
         xkVs5aZU21TM2l6o9RZusn1r39alZ2gI2icKVjk+ZH90u6gneQoUADz7Wd3s2J+7ESSK
         wAZL+K5f/L+E6CUqA/27HGdYagsqQFZCerV8TqtrtqIpjw76x3kXsqwAeIIG502qnU4w
         hiiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=uOpS3KalITgAIxnfa+Gfow9HlKtQi/88Aw/3+l8X7y0=;
        fh=6ri0NDGAXmoVkC6BpMACJbfcjis5kBT3lZdVMeIm4dY=;
        b=iChI1jd0R9hYiQuoiE/sq+jLdl6qoYzG29A/fEWkufdntjeAy8sldwR+9Qd+IXqnYp
         wAiYFdVTXDRKNTfs8yeXVHmllIAXpfPH6+UXYsNehNU47wURp/lLBs0Ozg0GPAs4rMFJ
         nseBNcY4Kd5lDkzqzis5ZpkaTJ6sw/YFU+Rv6S/1hEnQWGBkpl8zkEbZA6RArwJthejd
         skBNKhKYSked6fw4tRIuIq9zZQRWzoV9P7gniV1CqmBbEDs0artx52oSAbA8reWIxA01
         niQGn5x6TVj3Maq8J+XHV1i7tMR3QeXt+OTSxKyKBNwZTzhcqb/8A2kpjtcezcJsvakI
         e6fw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Mf15Wc3f;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::635 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x635.google.com (mail-ej1-x635.google.com. [2a00:1450:4864:20::635])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55b8870e498si376761e87.0.2025.08.05.22.00.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Aug 2025 22:00:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::635 as permitted sender) client-ip=2a00:1450:4864:20::635;
Received: by mail-ej1-x635.google.com with SMTP id a640c23a62f3a-af95ecfbd5bso571319066b.1
        for <kasan-dev@googlegroups.com>; Tue, 05 Aug 2025 22:00:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU/ubtlbYxCBQvk0ybuLADkevG2vzxDwqa5QneIPjY+FzoPU+OoAnG+VyJtpfbl+R5CS6KBOJ3ffA8=@googlegroups.com
X-Gm-Gg: ASbGncsm9wcHu+n4VUSbWnpa7m5xGMD6OmqcvFJK+DxSfKnjNWf9Jx8mMpOgB2fRxQ9
	wwYtTXKO2pFW9veAK7HFa0OAt4J7hY7O0VSuKTNsslNeEMqJ/Dx+plSrW9A9gXaeXxAHYBbdWgm
	Cv/lOlliXn0Xi5UBaSq3UYFcwl3dITogZfmAjx4PNNh/9HwVH+m9K0yzSK7t4+aXt40cFbcjjN/
	wM3h+dJezseYhA7ObI=
X-Received: by 2002:a17:907:3e1c:b0:ae3:4f80:ac4c with SMTP id
 a640c23a62f3a-af9900498camr123777066b.12.1754456409456; Tue, 05 Aug 2025
 22:00:09 -0700 (PDT)
MIME-Version: 1.0
From: smr adel <marwaipm1@gmail.com>
Date: Wed, 6 Aug 2025 08:00:00 +0300
X-Gm-Features: Ac12FXyNcJfsutNo6lWX8o_GAGPvrfJxvNzO5bYK9wikNPiSD0XHuTD-Czn2RAI
Message-ID: <CADj1ZK=RgHD3AOtRfk2qk=67onLVTpq=d-v2H=KjeRj_c02T_w@mail.gmail.com>
Subject: =?UTF-8?B?2YXYr9mK2LEg2KfZhNiq2KzYp9ix2Kkg2KfZhNin2YTZg9iq2LHZiNmG2YrYqSDZiNin?=
	=?UTF-8?B?2YTYqtit2YjZhCDYp9mE2LHZgtmF2Yog2KfZhNio2LHZhtin2YXYrCDYp9mE2YXYqtmD2KfZhdmEINmB?=
	=?UTF-8?B?2Yog2KfZhNiq2KzYp9ix2Kkg2KfZhNil2YTZg9iq2LHZiNmG2YrYqSBCMkIgJiBCMkMg2KfZhNmF2Yg=?=
	=?UTF-8?B?2KfYudmK2K8g2KfZhNmF2KrYp9it2Kk6INi52YYg2KjZj9i52K8g2LnYqNixIFpvb206INmF2YYgMTcg?=
	=?UTF-8?B?2KXZhNmJIDI2INij2LrYs9i32LMgMjAyNSDYrdi22YjYsdmKINmB2Yog2KfZhNmC2KfZh9ix2Kkg4oCT?=
	=?UTF-8?B?INmF2YLYsSDYp9mE2K/Yp9ixOiDZitmI2YUg2KfZhNij2K3YryA3INiz2KjYqtmF2KjYsSAyMDI1INi0?=
	=?UTF-8?B?2YfYp9iv2Kkg2YXZh9mG2YrYqSDZhdi52KrZhdiv2Kkg4oCTINmF2YjYq9mC2Kkg2YjYqNin2LnYqtmF?=
	=?UTF-8?B?2KfYryDYr9mI2YTZiiDZhdi52KrYsdmBINio2YfYpyDZgdmKINmD2KfZgdipINin2YTYr9mI2YQg2Kc=?=
	=?UTF-8?B?2YTYr9in2LEg2KfZhNi52LHYqNmK2Kkg2YTZhNiq2YbZhdmK2Kkg2KfZhNin2K/Yp9ix2YrYqSDigJMg?=
	=?UTF-8?B?QUhBRCDYqtit2YrYqSDYt9mK2KjYqSDZiCDYqNi52K8g2IzYjNiMINij2LfZitioINin2YTYo9mF2YY=?=
	=?UTF-8?B?2YrYp9iqINmI2KfZhNiq2K3Zitin2Kog2KrZh9iv2YrZh9inINmE2YPZhSDYp9mE2K/Yp9ixINin2YQ=?=
	=?UTF-8?B?2LnYsdio2YrYqSDZhNmE2KrZhtmF2YrYqSDYp9mE2KfYr9in2LHZitipINio2LTZh9in2K/YqSDZhdi5?=
	=?UTF-8?B?2KrZhdivIC0gQUhBRCDYtNmH2KfYr9ipINmF2KfYsNinINiz2KrYqti52YTZhTog4oCiINin2YTZgdix?=
	=?UTF-8?B?2YIg2KfZhNis2YjZh9ix2Yog2KjZitmGINmG2YXYp9iw2Kwg2KfZhNiq2KzYp9ix2Kkg2KfZhNil2YQ=?=
	=?UTF-8?B?2YPYqtix2YjZhtmK2KkgQjJCINmIQjJDINmI2YPZitmB2YrYqSDYp9iu2KrZitin2LEg2KfZhNij2YY=?=
	=?UTF-8?B?2LPYqCDZhNmG2LTYp9i32YMuIOKAoiDYrti32YjYp9iqINio2YbYp9ihINmF2KrYrNixINil2YTZg9iq?=
	=?UTF-8?B?2LHZiNmG2Yog2KfYrdiq2LHYp9mB2Yog2KjYp9iz2KrYrtiv2KfZhSDYo9iv2YjYp9iqIO+/vQ==?=
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="0000000000000f4930063bab37e4"
X-Original-Sender: marwaipm1@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Mf15Wc3f;       spf=pass
 (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::635
 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

--0000000000000f4930063bab37e4
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

KtmF2K/ZitixINin2YTYqtis2KfYsdipINin2YTYp9mE2YPYqtix2YjZhtmK2Kkg2YjYp9mE2KrY
rdmI2YQg2KfZhNix2YLZhdmKKg0KDQoq2KfZhNio2LHZhtin2YXYrCDYp9mE2YXYqtmD2KfZhdmE
INmB2Yog2KfZhNiq2KzYp9ix2Kkg2KfZhNil2YTZg9iq2LHZiNmG2YrYqSoqIEIyQiAmIEIyQyoN
Cg0KKtin2YTZhdmI2KfYudmK2K8g2KfZhNmF2KrYp9it2KkqKjoqDQoNCirYudmGINio2Y/Yudiv
INi52KjYsSoqIFpvb206KiDZhdmGICoxNyogKtil2YTZiSAyNiDYo9i62LPYt9izIDIwMjUqDQoN
CirYrdi22YjYsdmKINmB2Yog2KfZhNmC2KfZh9ix2Kkg4oCTINmF2YLYsSDYp9mE2K/Yp9ixKio6
KiDZitmI2YUgKtin2YTYo9it2K8gNyDYs9io2KrZhdio2LEgMjAyNSoNCg0KKti02YfYp9iv2Kkg
2YXZh9mG2YrYqSDZhdi52KrZhdiv2Kkg4oCTINmF2YjYq9mC2Kkg2YjYqNin2LnYqtmF2KfYryDY
r9mI2YTZiiogKtmF2LnYqtix2YEg2KjZh9inINmB2Yog2YPYp9mB2Kkg2KfZhNiv2YjZhCoNCg0K
Ktin2YTYr9in2LEg2KfZhNi52LHYqNmK2Kkg2YTZhNiq2YbZhdmK2Kkg2KfZhNin2K/Yp9ix2YrY
qSDigJMgKipBSEFEKg0KDQrYqtit2YrYqSDYt9mK2KjYqSDZiCDYqNi52K8g2IzYjNiMDQoNCtij
2LfZitioINin2YTYo9mF2YbZitin2Kog2YjYp9mE2KrYrdmK2KfYqiDYqtmH2K/ZitmH2Kcg2YTZ
g9mFINin2YTYr9in2LEg2KfZhNi52LHYqNmK2Kkg2YTZhNiq2YbZhdmK2Kkg2KfZhNin2K/Yp9ix
2YrYqSDYqNi02YfYp9iv2KkNCtmF2LnYqtmF2K8gLSBBSEFEDQoNCti02YfYp9iv2KkNCg0K2YXY
p9iw2Kcg2LPYqtiq2LnZhNmFOg0KDQrCtyAgICAgICAgICAgICAgICAgICDYp9mE2YHYsdmCINin
2YTYrNmI2YfYsdmKINio2YrZhiDZhtmF2KfYsNisINin2YTYqtis2KfYsdipINin2YTYpdmE2YPY
qtix2YjZhtmK2KkgQjJCINmIQjJDINmI2YPZitmB2YrYqQ0K2KfYrtiq2YrYp9ixINin2YTYo9mG
2LPYqCDZhNmG2LTYp9i32YMuDQoNCsK3ICAgICAgICAgICAgICAgICAgINiu2LfZiNin2Kog2KjZ
htin2KEg2YXYqtis2LEg2KXZhNmD2KrYsdmI2YbZiiDYp9it2KrYsdin2YHZiiDYqNin2LPYqtiu
2K/Yp9mFINij2K/ZiNin2Kog2YjZhdmG2LXYp9iqDQrYudin2YTZhdmK2KkuDQoNCsK3ICAgICAg
ICAgICAgICAgICAgINiq2LXZhdmK2YUg2KrYrNix2KjYqSDZhdiz2KrYrtiv2YUg2YXYqtmF2YrY
stipINiq2LPZh9mR2YQg2KfZhNi02LHYp9ihINmI2KrYstmK2K8g2YXZhiDZiNmE2KfYoQ0K2KfZ
hNi52YXZhNin2KEuDQoNCsK3ICAgICAgICAgICAgICAgICAgINiq2YbZgdmK2LAg2K3ZhdmE2KfY
qiDYqtiz2YjZitmCINix2YLZhdmKINmB2LnZkdin2YTYqSDYqNin2LPYqtiu2K/Yp9mFINin2YTY
pdi52YTYp9mG2KfYqtiMIFNFT9iMDQrZiNmI2LPYp9im2YQg2KfZhNiq2YjYp9i12YQuDQoNCsK3
ICAgICAgICAgICAgICAgICAgINil2K/Yp9ix2Kkg2LnZhdmE2YrYp9iqINin2YTYr9mB2LnYjCDY
p9mE2KrZiNi12YrZhNiMINmI2K7Yr9mF2Kkg2KfZhNi52YXZhNin2KEg2KjYtNmD2YQg2YXYqtmD
2KfZhdmEDQrZiNin2K3Yqtix2KfZgdmKLg0KDQrCtyAgICAgICAgICAgICAgICAgICDYqtit2YTZ
itmEINio2YrYp9mG2KfYqiDYp9mE2LLZiNin2LEg2YjYp9mE2YXYqNmK2LnYp9iqINmI2KfYqtiu
2KfYsCDZgtix2KfYsdin2Kog2YXYr9ix2YjYs9ipDQrZhNiq2K3Ys9mK2YYg2KfZhNij2K/Yp9ih
Lg0KDQrCtyAgICAgICAgICAgICAgICAgICDYqti32KjZitmCINij2K/ZiNin2Kog2KfZhNiw2YPY
p9ihINin2YTYp9i12LfZhtin2LnZiiDZgdmKINin2YTYqtiz2YjZitmCINmI2KfZhNiq2K3ZhNmK
2YQNCtmI2KfZhNiq2K7YtdmK2LUuDQoNCsK3ICAgICAgICAgICAgICAgICAgINin2LPYqtix2KfY
qtmK2KzZitin2Kog2KfZhNiq2YjYs9i5INmI2KfZhNmG2YXZiCDZgdmKINin2YTYs9mI2YIg2KfZ
hNmF2K3ZhNmKINmI2KfZhNi52KfZhNmF2YouDQoNCg0KDQrYo9mH2K/Yp9mBINin2YTYqNix2YbY
p9mF2Kw6DQoNCiAgIC0g2KrZhdmD2YrZhiDYp9mE2YXYtNin2LHZg9mK2YYg2YXZhiDZgdmH2YUg
2YbZhdin2LDYrCDYp9mE2KrYrNin2LHYqSDYp9mE2KXZhNmD2KrYsdmI2YbZitipIEIyQiDZiEIy
Qy4NCiAgIC0g2KjZhtin2KEg2YjYqti32YjZitixINmF2KrYp9is2LEg2KXZhNmD2KrYsdmI2YbZ
itipINin2K3Yqtix2KfZgdmK2Kkg2KrYqtmI2KfZgdmCINmF2Lkg2KfYrdiq2YrYp9is2KfYqiDY
p9mE2LnZhdmE2KfYoQ0KICAg2YjYp9mE2YXYpNiz2LPYp9iqLg0KICAgLSDYqti32KjZitmCINij
2K3Yr9irINin2YTYo9iv2YjYp9iqINmI2KfZhNmF2YbYtdin2Kog2YHZiiDYp9mE2KrYs9mI2YrZ
giDZiNin2YTYqNmK2Lkg2KfZhNil2YTZg9iq2LHZiNmG2YouDQogICAtINiq2K3ZhNmK2YQg2KjZ
itin2YbYp9iqINin2YTYstio2KfYptmGINmI2KrYrdiz2YrZhiDYqtis2LHYqNipINin2YTZhdiz
2KrYrtiv2YUg2LnYqNixINin2YTZgtmG2YjYp9iqINin2YTYsdmC2YXZitipLg0KICAgLSDYpdiv
2KfYsdipINi52YXZhNmK2KfYqiDYp9mE2K/Zgdi52Iwg2KfZhNi02K3ZhtiMINmI2K7Yr9mF2Kkg
2YXYpyDYqNi52K8g2KfZhNio2YrYuSDYqNmB2LnYp9mE2YrYqS4NCg0KDQoNCtin2YTZhdit2KfZ
iNixINin2YTYqtiv2LHZitio2YrYqToNCg0KKvCflLkqKiAxLiAqKtmF2YLYr9mF2Kkg2YHZiiDY
p9mE2KrYrNin2LHYqSDYp9mE2KXZhNmD2KrYsdmI2YbZitipKg0KDQogICAtICrYp9mE2YHYsdmC
INio2YrZhioqIEIyQiAqKtmIKipCMkMqDQogICAtICrYp9mE2KfYqtis2KfZh9in2Kog2KfZhNi5
2KfZhNmF2YrYqSDZiNin2YTZhdit2YTZitipINmB2Yog2KfZhNiq2KzYp9ix2Kkg2KfZhNix2YLZ
hdmK2KkqDQogICAtICrYudmG2KfYtdixINin2YTZhtis2KfYrSDZgdmKINin2YTYo9i52YXYp9mE
INin2YTYpdmE2YPYqtix2YjZhtmK2KkqDQoNCirwn5S5KiogMi4gKirYqti12YXZitmFINmI2KXY
t9mE2KfZgiDZhdiq2KzYsSDYpdmE2YPYqtix2YjZhtmKKg0KDQogICAtICrYp9iu2KrZitin2LEg
2KfZhNmF2YbYtdin2Kog2KfZhNmF2YbYp9iz2KjYqSoqIChTaG9waWZ5IOKAkyBXb29Db21tZXJj
ZSDigJMgTWFnZW50bykqDQogICAtICrYpdi52K/Yp9ivINin2YTZhdmG2KrYrNin2Kog2YjYp9mE
2KjZiNin2KjYp9iqINin2YTYpdmE2YPYqtix2YjZhtmK2Kkg2YTZhNiv2YHYuSoNCiAgIC0gKtiq
2KzYsdio2Kkg2KfZhNmF2LPYqtiu2K/ZhSoqIFVYIC8gKirZiNin2KzZh9ipINin2YTZhdiz2KrY
rtiv2YUqKiBVSSoNCg0KKvCflLkqKiAzLiAqKtin2YTYqtiz2YjZitmCINin2YTYsdmC2YXZiiDZ
hNmE2KrYrNin2LHYqSDYp9mE2KXZhNmD2KrYsdmI2YbZitipKg0KDQogICAtICrYp9iz2KrYsdin
2KrZitis2YrYp9iqINin2YTYqtiz2YjZitmCINio2KfZhNmF2K3YqtmI2Ykg2YjYp9mE2KXYudmE
2KfZhtin2Kog2KfZhNmF2YXZiNmE2KkqDQogICAtICrYp9mE2KrYs9mI2YrZgiDYudio2LEg2YjY
s9in2KbZhCDYp9mE2KrZiNin2LXZhCDZiNmF2K3YsdmD2KfYqiDYp9mE2KjYrdirKiogU0VPL1NF
TSoNCiAgIC0gKtin2LPYqtiu2K/Yp9mFINij2K/ZiNin2Kog2KfZhNiw2YPYp9ihINin2YTYp9i1
2LfZhtin2LnZiiDZgdmKINin2YTYrdmF2YTYp9iqINin2YTYpdi52YTYp9mG2YrYqSoNCg0KKvCf
lLkqKiA0LiAqKtil2K/Yp9ix2Kkg2KfZhNi52YXZhNmK2KfYqiDYp9mE2KXZhNmD2KrYsdmI2YbZ
itipKg0KDQogICAtICrYpdiv2KfYsdipINin2YTZhdiu2LLZiNmGINmI2LPZhNin2LPZhCDYp9mE
2KXZhdiv2KfYryoNCiAgIC0gKtiq2YPYp9mF2YQg2KfZhNi02K3ZhiDZiNin2YTYqtmI2LXZitmE
INmF2Lkg2KfZhNmF2KrYrNixKg0KICAgLSAq2KXYr9in2LHYqSDYsdi22Kcg2KfZhNi52YXZhNin
2KEg2YjYrtiv2YXYqSDZhdinINio2LnYryDYp9mE2KjZiti5Kg0KDQoq8J+UuSoqIDUuICoq2KrY
rdmE2YrZhCDYp9mE2KPYr9in2KEg2YjYp9mE2KrZiNiz2LkqDQoNCiAgIC0gKtin2LPYqtiu2K/Y
p9mFKiogR29vZ2xlIEFuYWx5dGljcyAqKtmIKipNZXRhIEJ1c2luZXNzIFN1aXRlKg0KICAgLSAq
2KrZgtin2LHZitixINin2YTYo9iv2KfYoSDZiNmF2KTYtNix2KfYqioqIEtQSSoNCiAgIC0gKtin
2LPYqtix2KfYqtmK2KzZitin2Kog2KfZhNiq2YjYs9i5INmB2Yog2KfZhNiz2YjZgiDYp9mE2YXY
rdmE2Yog2YjYp9mE2K/ZiNmE2YoqDQoNCg0KDQrYp9mE2YHYptipINin2YTZhdiz2KrZh9iv2YHY
qToNCg0KICAgLSDYsdmI2KfYryDYp9mE2KPYudmF2KfZhCDZiNij2LXYrdin2Kgg2KfZhNmF2LTY
p9ix2YrYuSDYp9mE2KXZhNmD2KrYsdmI2YbZitipDQogICAtINmB2LHZgiDYp9mE2KrYs9mI2YrZ
giDZiNin2YTZhdio2YrYudin2KoNCiAgIC0g2YXYr9ix2KfYoSDYp9mE2KrYrNin2LHYqSDYp9mE
2KXZhNmD2KrYsdmI2YbZitipINmI2KfZhNiq2K3ZiNmEINin2YTYsdmC2YXZig0KICAgLSDYo9mK
INi02K7YtSDZiti32YXYrSDZhNiv2K7ZiNmEINi52KfZhNmFINin2YTYqNmK2Lkg2LnYqNixINin
2YTYpdmG2KrYsdmG2KoNCg0KDQoNCirYtNmH2KfYr9in2Kog2YXYudiq2YXYr9ipINiv2YjZhNmK
2Kcg2YjZhdit2YTZitinINmF2YYg2YjYstin2LHYqSDYp9mE2K7Yp9ix2KzZitipINmI2KfZhNiz
2YHYp9ix2Kkg2KfZhNmC2YbYtdmE2YrYqSoNCg0KKtmF2LnYqtmF2K8gLyAqKkFIQUQqDQoNCirY
qtmC2K/ZhdipINin2YTYr9in2LEg2KfZhNi52LHYqNmK2Kkg2YTZhNiq2YbZhdmK2Kkg2KfZhNin
2K/Yp9ix2YrYqSoNCg0KKvCfk4oqICrYrNiv2YjZhCDYp9mE2K/ZiNix2KfYqiDYp9mE2YXYp9mE
2YrYqSDZiNin2YTZhdit2KfYs9io2YrYqSoNCg0KKvCfl5PvuI8qICrZhdmGINiz2KjYqtmF2KjY
sSDYpdmE2Ykg2K/Zitiz2YXYqNixIDIwMjUqDQoq8J+OkyogKtmF2YLYr9mF2Kkg2YXZhiDYp9mE
2K/Yp9ixINin2YTYudix2KjZitipINmE2YTYqtmG2YXZitipINin2YTYpdiv2KfYsdmK2KkqDQoq
8J+TjSogKtiv2KjZiiDigJMg2KXYs9i32YbYqNmI2YQg4oCTINmF2KfZhNmK2LLZitinKg0KKvCf
k5wqICrYtNmH2KfYr9in2Kog2YXYudiq2YXYr9ipINmC2KfYqNmE2Kkg2YTZhNiq2LXYr9mK2YIg
2YXZhiDZg9in2YHYqSDYp9mE2LPZgdin2LHYp9iqINin2YTYudix2KjZitipKg0KKiAtLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKg0KDQoq4pyFKiAq2LPYqNiq2YXYqNixIDIwMjUqDQoN
CirYp9mE2K/ZiNix2KkqDQoNCirYp9mE2YXZg9in2YYqDQoNCirYp9mE2KrYp9ix2YrYrioNCg0K
Ktin2YTYsdiz2YjZhSoNCg0KKtin2YTYqtit2YTZitmEINin2YTZhdin2YTZiiDZiNiq2YLZitmK
2YUg2KfZhNij2K/Yp9ihINin2YTZhdik2LPYs9mKKg0KDQoq2KXYs9i32YbYqNmI2YQqDQoNCio3
IOKAkyAxMSAqKtiz2KjYqtmF2KjYsSoNCg0KKjEsNDAwICoq2K/ZiNmE2KfYsSoNCg0KKtil2LnY
r9in2K8g2KfZhNmF2YjYp9iy2YbYp9iqINmI2KfZhNiq2K3Zg9mFINmB2Yog2KfZhNiq2YPYp9mE
2YrZgSoNCg0KKtiv2KjZiioNCg0KKjE0IOKAkyAxOCAqKtiz2KjYqtmF2KjYsSoNCg0KKjE3NTAq
ICrYr9mI2YTYp9ixKg0KDQoq2KfZhNmF2K3Yp9iz2KjYqSDYp9mE2K3Zg9mI2YXZitipINmI2YHZ
gioqIElQU0FTKg0KDQoq2K/YqNmKKg0KDQoqMjEg4oCTIDI1ICoq2LPYqNiq2YXYqNixKg0KDQoq
MTc1MCogKtiv2YjZhNin2LEqDQoNCirZhdit2KfYs9io2Kkg2KfZhNiq2YPYp9mE2YrZgSDZiNiq
2K3ZhNmK2YQg2KfZhNin2YbYrdix2KfZgdin2KoqDQoNCirYpdiz2LfZhtio2YjZhCoNCg0KKjIx
IOKAkyAyNSAqKtiz2KjYqtmF2KjYsSoNCg0KKjEsNDAwICoq2K/ZiNmE2KfYsSoNCg0KKtin2YTY
o9iz2LMg2KfZhNit2K/Zitir2Kkg2YHZiiDYpdi52K/Yp9ivINin2YTYqtmC2KfYsdmK2LEg2KfZ
hNmF2KfZhNmK2KkqDQoNCirZhdin2YTZitiy2YrYpyoNCg0KKjI4ICoq2LPYqNiq2YXYqNixIOKA
kyAyINij2YPYqtmI2KjYsSoNCg0KKjIwMDAqICrYr9mI2YTYp9ixKg0KDQoq2KfZhNiq2K3ZhNmK
2YQg2KfZhNmF2KfZhNmKINio2KfYs9iq2K7Yr9in2YUqKiBFeGNlbCoNCg0KKtiv2KjZiioNCg0K
KjI4ICoq2LPYqNiq2YXYqNixIOKAkyAyINij2YPYqtmI2KjYsSoNCg0KKjE3NTAqICrYr9mI2YTY
p9ixKg0KKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKg0KDQoq4pyFKiAq2KPZg9iq
2YjYqNixIDIwMjUqDQoNCirYp9mE2K/ZiNix2KkqDQoNCirYp9mE2YXZg9in2YYqDQoNCirYp9mE
2KrYp9ix2YrYrioNCg0KKtin2YTYsdiz2YjZhSoNCg0KKtin2YTZhdit2KfYs9io2Kkg2YjYp9mE
2KfYqti12KfZhCDYp9mE2YXYp9mE2Yog2YjYp9iq2K7Yp9iwINin2YTZgtix2KfYsSoNCg0KKtiv
2KjZiioNCg0KKjUg4oCTIDkgKirYo9mD2KrZiNio2LEqDQoNCioxNzUwKiAq2K/ZiNmE2KfYsSoN
Cg0KKtin2YTZhdix2KfYrNi52Kkg2YjYp9mE2KrYr9mC2YrZgiDYp9mE2YXYp9mE2Yog2YjYp9mE
2LbYsdmK2KjZiioNCg0KKtil2LPYt9mG2KjZiNmEKg0KDQoqNSDigJMgOSAqKtij2YPYqtmI2KjY
sSoNCg0KKjEsNDAwICoq2K/ZiNmE2KfYsSoNCg0KKtin2YTZhdit2KfYs9io2Kkg2KfZhNit2YPZ
iNmF2YrYqSDYp9mE2YXYqtmC2K/ZhdipKg0KDQoq2YXYp9mE2YrYstmK2KcqDQoNCioxMiDigJMg
MTYgKirYo9mD2KrZiNio2LEqDQoNCioyMDAwKiAq2K/ZiNmE2KfYsSoNCg0KKtil2LnYr9in2K8g
2KfZhNit2LPYp9io2KfYqiDYp9mE2K7Yqtin2YXZitipINmI2KfZhNiq2LPZiNmK2KfYqiDYp9mE
2KzYsdiv2YrYqSoNCg0KKtiv2KjZiioNCg0KKjE5IOKAkyAyMyAqKtij2YPYqtmI2KjYsSoNCg0K
KjE3NTAqICrYr9mI2YTYp9ixKg0KDQoq2KXYudiv2KfYryDYp9mE2YLZiNin2KbZhSDYp9mE2YXY
p9mE2YrYqSDZiNmB2YIqKiBJRlJTKg0KDQoq2KXYs9i32YbYqNmI2YQqDQoNCioxOSDigJMgMjMg
KirYo9mD2KrZiNio2LEqDQoNCioxLDQwMCAqKtiv2YjZhNin2LEqDQoNCirYqtiu2LfZiti3INin
2YTZhdmI2KfYstmG2KfYqiDZiNix2YLYp9io2Kkg2KfZhNiq2YPYp9mE2YrZgSoNCg0KKtiv2KjZ
iioNCg0KKjI2IOKAkyAzMCAqKtij2YPYqtmI2KjYsSoNCg0KKjE3NTAqICrYr9mI2YTYp9ixKg0K
KiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKg0KDQoq4pyFKiAq2YbZiNmB2YXYqNix
IDIwMjUqDQoNCirYp9mE2K/ZiNix2KkqDQoNCirYp9mE2YXZg9in2YYqDQoNCirYp9mE2KrYp9ix
2YrYrioNCg0KKtin2YTYsdiz2YjZhSoNCg0KKtin2YTZhtmF2LDYrNipINin2YTZhdin2YTZitip
INio2KfYs9iq2K7Yr9in2YUqKiBFeGNlbCAqKtmIKipQb3dlciBCSSoNCg0KKtil2LPYt9mG2KjZ
iNmEKg0KDQoqMiDigJMgNiAqKtmG2YjZgdmF2KjYsSoNCg0KKjEsNDAwICoq2K/ZiNmE2KfYsSoN
Cg0KKtil2K/Yp9ix2Kkg2YjZhdit2KfYs9io2Kkg2KfZhNij2LXZiNmEINin2YTYq9in2KjYqtip
Kg0KDQoq2K/YqNmKKg0KDQoqMiDigJMgNiAqKtmG2YjZgdmF2KjYsSoNCg0KKjE3NTAqICrYr9mI
2YTYp9ixKg0KDQoq2KfZhNiq2K3ZhNmK2YQg2KfZhNmF2KfZhNmKINin2YTZhdiq2YLYr9mFKg0K
DQoq2YXYp9mE2YrYstmK2KcqDQoNCio5IOKAkyAxMyAqKtmG2YjZgdmF2KjYsSoNCg0KKjIwMDAq
ICrYr9mI2YTYp9ixKg0KDQoq2KXYudiv2KfYryDYr9ix2KfYs9in2Kog2KfZhNis2K/ZiNmJINmI
2KfZhNiq2YXZiNmK2YQg2KfZhNin2LPYqtix2KfYqtmK2KzZiioNCg0KKtiv2KjZiioNCg0KKjE2
IOKAkyAyMCAqKtmG2YjZgdmF2KjYsSoNCg0KKjE3NTAqICrYr9mI2YTYp9ixKg0KDQoq2YXYsdin
2YLYqNipINin2YTYo9iv2KfYoSDYp9mE2YXYp9mE2Yog2YjYqtmC2KfYsdmK2LEg2KfZhNil2K/Y
p9ix2KkqDQoNCirYpdiz2LfZhtio2YjZhCoNCg0KKjIzIOKAkyAyNyAqKtmG2YjZgdmF2KjYsSoN
Cg0KKjEsNDAwICoq2K/ZiNmE2KfYsSoNCg0KKtin2YTYsdmC2KfYqNipINin2YTZhdin2YTZitip
INmI2KfZhNin2YXYqtir2KfZhCDZhNmE2YXZiNin2LLZhtin2KoqDQoNCirYr9io2YoqDQoNCioy
MyDigJMgMjcgKirZhtmI2YHZhdio2LEqDQoNCioxNzUwKiAq2K/ZiNmE2KfYsSoNCiogLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICoNCg0KKuKchSogKtiv2YrYs9mF2KjYsSAyMDI1Kg0K
DQoq2KfZhNiv2YjYsdipKg0KDQoq2KfZhNmF2YPYp9mGKg0KDQoq2KfZhNiq2KfYsdmK2K4qDQoN
CirYp9mE2LHYs9mI2YUqDQoNCirYpdi52K/Yp9ivINin2YTYqtmC2KfYsdmK2LEg2KfZhNmF2KfZ
hNmK2KkqKiBJRlJTKg0KDQoq2YXYp9mE2YrYstmK2KcqDQoNCioxIOKAkyA1ICoq2K/Zitiz2YXY
qNixKg0KDQoqMjAwMCogKtiv2YjZhNin2LEqDQoNCirYpdiv2KfYsdipINin2YTZhdiu2KfYt9ix
INin2YTZhdin2YTZitipINmI2KfZhNiq2K7Yt9mK2Lcg2KfZhNmF2KfZhNmKKg0KDQoq2K/YqNmK
Kg0KDQoqOCDigJMgMTIgKirYr9mK2LPZhdio2LEqDQoNCioxNzUwKiAq2K/ZiNmE2KfYsSoNCg0K
Ktil2K/Yp9ix2Kkg2KfZhNmG2YLYryDZiNin2YTYqtiv2YHZgtin2Kog2KfZhNmF2KfZhNmK2Kkq
DQoNCirYpdiz2LfZhtio2YjZhCoNCg0KKjgg4oCTIDEyICoq2K/Zitiz2YXYqNixKg0KDQoqMSw0
MDAgKirYr9mI2YTYp9ixKg0KDQoq2KfZhNmF2K3Yp9iz2KjYqSDZiNin2YTYqtit2YTZitmEINin
2YTZhdin2YTZiiDZhNi62YrYsSDYp9mE2YXYrdin2LPYqNmK2YYqDQoNCirYr9io2YoqDQoNCiox
NSDigJMgMTkgKirYr9mK2LPZhdio2LEqDQoNCioxNzUwKiAq2K/ZiNmE2KfYsSoNCg0KKtil2LnY
r9in2K8g2KfZhNmF2YrYstin2YbZitin2Kog2YjYqNix2KfZhdisINin2YTYsdmC2KfYqNipINin
2YTZhdin2YTZitipKg0KDQoq2K/YqNmKKg0KDQoqMjIg4oCTIDI2ICoq2K/Zitiz2YXYqNixKg0K
DQoqMTc1MCogKtiv2YjZhNin2LEqDQoNCirZhdit2KfYs9io2Kkg2KfZhNiq2YPYp9mE2YrZgSDY
p9mE2YXYqtmC2K/ZhdipINmI2KfYqtiu2KfYsCDYp9mE2YLYsdin2LEqDQoNCirYpdiz2LfZhtio
2YjZhCoNCg0KKjIyIOKAkyAyNiAqKtiv2YrYs9mF2KjYsSoNCg0KKjEsNDAwICoq2K/ZiNmE2KfY
sSoNCiogLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICoNCg0KKvCfjq8qICrZhdmF2YrY
stin2Kog2KfZhNiv2YjYsdin2KoqKjoqDQoNCirCtyAgICAgICAgICAgICAgICAgICAqKtiq2YbZ
gdmK2LAg2K3YttmI2LHZiiDYo9mIINi52KjYsSoqIFpvb20qDQoNCirCtyAgICAgICAgICAgICAg
ICAgICAqKtiq2K/YsdmK2Kgg2LnZhdmE2Yog2YjZhdmH2YbZiioNCg0KKsK3ICAgICAgICAgICAg
ICAgICAgICoq2K7YtdmI2YXYp9iqINiu2KfYtdipINmE2YTZhdis2YXZiNi52KfYqiDZiNin2YTY
rNmH2KfYqiDYp9mE2K3Zg9mI2YXZitipKg0KDQoNCg0KKtmI2KjZh9iw2Ycg2KfZhNmF2YbYp9iz
2KjYqSDZitiz2LnYr9mG2Kcg2K/YudmI2KrZg9mFINmE2YTZhdi02KfYsdmD2Kkg2YjYqti52YXZ
itmFINiu2LfYp9io2YbYpyDYudmE2Ykg2KfZhNmF2YfYqtmF2YrZhg0K2KjZhdmA2YDZiNi22YDZ
iNi5ICoq2KfZhNi02YfYp9iv2Kkg2KfZhNin2K3Yqtix2KfZgdmK2KkgKirZiNil2YHYp9iv2KrZ
htinINio2YXZhiDYqtmC2KrYsdit2YjZhiDYqtmI2KzZitmHINin2YTYr9i52YjYqSDZhNmH2YUq
DQoNCirZhNmF2LLZitivINmF2YYg2KfZhNmF2LnZhNmI2YXYp9iqINmK2YXZg9mG2YMg2KfZhNiq
2YjYp9i12YQg2YXYuSDYoyAvINiz2KfYsdipINi52KjYryDYp9mE2KzZiNin2K8g4oCTINmG2KfY
ptioINmF2K/ZitixDQrYp9mE2KrYr9ix2YrYqCDigJMg2KfZhNiv2KfYsSDYp9mE2LnYsdio2YrY
qSDZhNmE2KrZhtmF2YrYqSDYp9mE2KfYr9in2LHZitipKg0KDQoq2KzZiNin2YQg4oCTINmI2KfY
qtizINin2KggOioNCg0KKjAwMjAxMDY5OTk0Mzk5IC0wMDIwMTA2Mjk5MjUxMCAtIDAwMjAxMDk2
ODQxNjI2Kg0KDQoNCg0KKuKchSogKtmF2YTYp9it2LjYp9iqINi52KfZhdipKio6Kg0KDQoq2KzZ
hdmK2Lkg2KfZhNi02YfYp9iv2KfYqiDYqti02YXZhCDYtNmH2KfYr9ipINmF2LnYqtmF2K/YqdiM
INit2YLZitio2Kkg2KrYr9ix2YrYqNmK2KnYjCDZiNmI2LHYtCDYudmF2YQg2KrZgdin2LnZhNmK
2KkqKi4qDQoNCtmK2YXZg9mGINiq2YbZgdmK2LAg2KfZhNio2LHYp9mF2KwgKtit2LbZiNix2YrZ
i9inINij2Ygg2KPZiNmG2YTYp9mK2YYg2LnYqNixKiogWm9vbSouDQoNCtil2YXZg9in2YbZitip
INiq2K7YtdmK2LUg2KPZiiDYtNmH2KfYr9ipINmE2KrZg9mI2YYgKtiv2KfYrtmEINin2YTYtNix
2YPYqSoqIChJbi1Ib3VzZSkqLg0KDQoq2YTZhNiq2LPYrNmK2YQg2YjYp9mE2KfYs9iq2YHYs9in
2LEqDQoNCirZiNio2YfYsNmHINin2YTZhdmG2KfYs9io2Kkg2YrYs9i52K/ZhtinINiv2LnZiNiq
2YPZhSDZhNmE2YXYtNin2LHZg9ipINmI2KrYudmF2YrZhSDYrti32KfYqNmG2Kcg2LnZhNmJINin
2YTZhdmH2KrZhdmK2YYNCtio2YXZgNmA2YjYttmA2YjYuSAqKtin2YTYtNmH2KfYr9ipINin2YTY
p9it2KrYsdin2YHZitipICoq2YjYpdmB2KfYr9iq2YbYpyDYqNmF2YYg2KrZgtiq2LHYrdmI2YYg
2KrZiNis2YrZhyDYp9mE2K/YudmI2Kkg2YTZh9mFKg0KDQoq2YTZhdiy2YrYryDZhdmGINin2YTZ
hdi52YTZiNmF2KfYqiDZitmF2YPZhtmDINin2YTYqtmI2KfYtdmEINmF2Lkg2KMgLyDYs9in2LHY
qSDYudio2K8g2KfZhNis2YjYp9ivIOKAkyDZhtin2KbYqCDZhdiv2YrYsQ0K2KfZhNiq2K/YsdmK
2Kgg4oCTINin2YTYr9in2LEg2KfZhNi52LHYqNmK2Kkg2YTZhNiq2YbZhdmK2Kkg2KfZhNin2K/Y
p9ix2YrYqSoNCg0KKtis2YjYp9mEIOKAkyDZiNin2KrYsyDYp9ioIDoqDQoNCiowMDIwMTA2OTk5
NDM5OSAtMDAyMDEwNjI5OTI1MTAgLSAwMDIwMTA5Njg0MTYyNioNCg0KLS0gCllvdSByZWNlaXZl
ZCB0aGlzIG1lc3NhZ2UgYmVjYXVzZSB5b3UgYXJlIHN1YnNjcmliZWQgdG8gdGhlIEdvb2dsZSBH
cm91cHMgImthc2FuLWRldiIgZ3JvdXAuClRvIHVuc3Vic2NyaWJlIGZyb20gdGhpcyBncm91cCBh
bmQgc3RvcCByZWNlaXZpbmcgZW1haWxzIGZyb20gaXQsIHNlbmQgYW4gZW1haWwgdG8ga2FzYW4t
ZGV2K3Vuc3Vic2NyaWJlQGdvb2dsZWdyb3Vwcy5jb20uClRvIHZpZXcgdGhpcyBkaXNjdXNzaW9u
IHZpc2l0IGh0dHBzOi8vZ3JvdXBzLmdvb2dsZS5jb20vZC9tc2dpZC9rYXNhbi1kZXYvQ0FEajFa
SyUzRFJnSEQzQU90UmZrMnFrJTNENjdvbkxWVHBxJTNEZC12MkglM0RLamVSal9jMDJUX3clNDBt
YWlsLmdtYWlsLmNvbS4K
--0000000000000f4930063bab37e4
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"rtl"><p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;l=
ine-height:106%;font-size:11pt;font-family:Calibri,sans-serif"><b><span lan=
g=3D"AR-SA" style=3D"font-size:22pt;line-height:106%;font-family:Arial,sans=
-serif;color:black">=D9=85=D8=AF=D9=8A=D8=B1 =D8=A7=D9=84=D8=AA=D8=AC=D8=A7=
=D8=B1=D8=A9
=D8=A7=D9=84=D8=A7=D9=84=D9=83=D8=AA=D8=B1=D9=88=D9=86=D9=8A=D8=A9 =D9=88=
=D8=A7=D9=84=D8=AA=D8=AD=D9=88=D9=84 =D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A</=
span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:106%;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=
=3D"font-size:22pt;line-height:106%;font-family:Arial,sans-serif;color:rgb(=
238,0,0)">=D8=A7=D9=84=D8=A8=D8=B1=D9=86=D8=A7=D9=85=D8=AC =D8=A7=D9=84=D9=
=85=D8=AA=D9=83=D8=A7=D9=85=D9=84 =D9=81=D9=8A =D8=A7=D9=84=D8=AA=D8=AC=D8=
=A7=D8=B1=D8=A9
=D8=A7=D9=84=D8=A5=D9=84=D9=83=D8=AA=D8=B1=D9=88=D9=86=D9=8A=D8=A9</span></=
b><span dir=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" st=
yle=3D"font-size:22pt;line-height:106%;color:rgb(238,0,0)"><span dir=3D"LTR=
"></span><span dir=3D"LTR"></span> B2B &amp; B2C</span></b><b><span lang=3D=
"AR-SA" style=3D"font-size:22pt;line-height:106%;font-family:Arial,sans-ser=
if;color:rgb(238,0,0)"></span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:106%;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=
=3D"font-size:16pt;line-height:106%;font-family:Arial,sans-serif">=D8=A7=D9=
=84=D9=85=D9=88=D8=A7=D8=B9=D9=8A=D8=AF =D8=A7=D9=84=D9=85=D8=AA=D8=A7=D8=
=AD=D8=A9</span></b><span dir=3D"LTR"></span><span dir=3D"LTR"></span><b><s=
pan dir=3D"LTR" style=3D"font-size:16pt;line-height:106%"><span dir=3D"LTR"=
></span><span dir=3D"LTR"></span>:</span></b><span dir=3D"LTR" style=3D"fon=
t-size:16pt;line-height:106%"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.2=
5in 8pt 0in;text-align:center;direction:rtl;unicode-bidi:embed;line-height:=
106%;font-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA"=
 style=3D"font-size:16pt;line-height:106%;font-family:Arial,sans-serif">=D8=
=B9=D9=86 =D8=A8=D9=8F=D8=B9=D8=AF =D8=B9=D8=A8=D8=B1</span></b><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font=
-size:16pt;line-height:106%"><span dir=3D"LTR"></span><span dir=3D"LTR"></s=
pan> Zoom:</span></b><span dir=3D"LTR" style=3D"font-size:16pt;line-height:=
106%"> </span><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106%=
;font-family:Arial,sans-serif">=D9=85=D9=86 <b><span style=3D"color:rgb(238=
,0,0)">17</span></b></span><span dir=3D"LTR"></span><span dir=3D"LTR"></spa=
n><b><span lang=3D"AR-SA" dir=3D"LTR" style=3D"font-size:16pt;line-height:1=
06%;color:rgb(238,0,0)"><span dir=3D"LTR"></span><span dir=3D"LTR"></span> =
</span></b><b><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106%=
;font-family:Arial,sans-serif;color:rgb(238,0,0)">=D8=A5=D9=84=D9=89 26 =D8=
=A3=D8=BA=D8=B3=D8=B7=D8=B3 2025</span></b><span dir=3D"LTR" style=3D"font-=
size:16pt;line-height:106%"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.2=
5in 8pt 0in;text-align:center;direction:rtl;unicode-bidi:embed;line-height:=
106%;font-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA"=
 style=3D"font-size:16pt;line-height:106%;font-family:Arial,sans-serif">=D8=
=AD=D8=B6=D9=88=D8=B1=D9=8A =D9=81=D9=8A
=D8=A7=D9=84=D9=82=D8=A7=D9=87=D8=B1=D8=A9 =E2=80=93 =D9=85=D9=82=D8=B1 =D8=
=A7=D9=84=D8=AF=D8=A7=D8=B1</span></b><span dir=3D"LTR"></span><span dir=3D=
"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%;=
color:black"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>:</span></b>=
<span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%;color:rgb(238,0,=
0)"> </span><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106%;f=
ont-family:Arial,sans-serif;color:rgb(238,0,0)">=D9=8A=D9=88=D9=85 <b>=D8=
=A7=D9=84=D8=A3=D8=AD=D8=AF 7 =D8=B3=D8=A8=D8=AA=D9=85=D8=A8=D8=B1 2025</b>=
</span><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%"></span><=
/p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:106%;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:106%;font-family:Arial,sans-serif">=D8=B4=D9=
=87=D8=A7=D8=AF=D8=A9 =D9=85=D9=87=D9=86=D9=8A=D8=A9 =D9=85=D8=B9=D8=AA=D9=
=85=D8=AF=D8=A9 =E2=80=93 =D9=85=D9=88=D8=AB=D9=82=D8=A9 =D9=88=D8=A8=D8=A7=
=D8=B9=D8=AA=D9=85=D8=A7=D8=AF =D8=AF=D9=88=D9=84=D9=8A</span></b><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span><b><span lang=3D"AR-SA" dir=3D"LTR=
" style=3D"font-size:20pt;line-height:106%"><span dir=3D"LTR"></span><span =
dir=3D"LTR"></span>
</span></b><b><span lang=3D"AR-SA" style=3D"font-size:20pt;line-height:106%=
;font-family:Arial,sans-serif">=D9=85=D8=B9=D8=AA=D8=B1=D9=81 =D8=A8=D9=87=
=D8=A7 =D9=81=D9=8A =D9=83=D8=A7=D9=81=D8=A9 =D8=A7=D9=84=D8=AF=D9=88=D9=84=
</span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:106%;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:106%;font-family:Arial,sans-serif">=D8=A7=D9=
=84=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9 =D9=84=D9=
=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=A7=D8=AF=D8=A7=D8=B1=D9=
=8A=D8=A9 =E2=80=93 </span></b><b><span dir=3D"LTR" style=3D"font-size:20pt=
;line-height:106%">AHAD</span></b><b><span lang=3D"AR-SA" style=3D"font-siz=
e:20pt;line-height:106%;font-family:Arial,sans-serif"></span></b></p>

<p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=3D"=
text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28p=
t;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"><=
span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times New Rom=
an&quot;,serif">=D8=AA=D8=AD=D9=8A=D8=A9 =D8=B7=D9=8A=D8=A8=D8=A9 =D9=88
=D8=A8=D8=B9=D8=AF =D8=8C=D8=8C=D8=8C</span></p>

<p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D"t=
ext-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font-s=
ize:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0=
.5pt"><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A3=D8=B7=D9=8A=D8=A8 =D8=A7=D9=84=D8=A3=D9=85=D9=
=86=D9=8A=D8=A7=D8=AA
=D9=88=D8=A7=D9=84=D8=AA=D8=AD=D9=8A=D8=A7=D8=AA=C2=A0=D8=AA=D9=87=D8=AF=D9=
=8A=D9=87=D8=A7 =D9=84=D9=83=D9=85=C2=A0=D8=A7=D9=84=D8=AF=D8=A7=D8=B1 =D8=
=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=D9=
=8A=D8=A9 =D8=A7=D9=84=D8=A7=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9</span><span lang=
=3D"AR-JO" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,=
serif">=C2=A0=D8=A8=D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=
=D8=AF
-=C2=A0</span><span dir=3D"LTR" style=3D"font-size:18pt">AHAD</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:106%;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"=
font-size:16pt;line-height:106%;font-family:Arial,sans-serif">=D8=B4=D9=87=
=D8=A7=D8=AF=D8=A9</span><b><span lang=3D"AR-SA" style=3D"font-family:Arial=
,sans-serif"></span></b></p>

<p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=3D"=
text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28p=
t;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"><=
span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New Rom=
an&quot;,serif;color:rgb(192,0,0)">=D9=85=D8=A7=D8=B0=D8=A7
=D8=B3=D8=AA=D8=AA=D8=B9=D9=84=D9=85</span><span dir=3D"LTR"></span><span d=
ir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:22pt;color:rgb(192,0=
,0)"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>:</span></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"margin:0in 0.5in 0in 0in;text-align:center;direction:rtl;unicode-bidi:embe=
d;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-sp=
acing:-0.5pt"><span style=3D"font-size:10pt;font-family:Symbol">=C2=B7<span=
 style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-featu=
re-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;fon=
t-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:22pt;font-family:&quot;Times New Roman&quot;,serif">=D8=A7=D9=84=D9=81=
=D8=B1=D9=82 =D8=A7=D9=84=D8=AC=D9=88=D9=87=D8=B1=D9=8A
=D8=A8=D9=8A=D9=86 =D9=86=D9=85=D8=A7=D8=B0=D8=AC =D8=A7=D9=84=D8=AA=D8=AC=
=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=A5=D9=84=D9=83=D8=AA=D8=B1=D9=88=D9=86=
=D9=8A=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span =
dir=3D"LTR" style=3D"font-size:22pt"><span dir=3D"LTR"></span><span dir=3D"=
LTR"></span> B2B
</span><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times=
 New Roman&quot;,serif">=D9=88</span><span dir=3D"LTR" style=3D"font-size:2=
2pt">B2C
</span><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times=
 New Roman&quot;,serif">=D9=88=D9=83=D9=8A=D9=81=D9=8A=D8=A9 =D8=A7=D8=AE=
=D8=AA=D9=8A=D8=A7=D8=B1 =D8=A7=D9=84=D8=A3=D9=86=D8=B3=D8=A8 =D9=84=D9=86=
=D8=B4=D8=A7=D8=B7=D9=83</span><span dir=3D"LTR"></span><span dir=3D"LTR"><=
/span><span dir=3D"LTR" style=3D"font-size:22pt"><span dir=3D"LTR"></span><=
span dir=3D"LTR"></span>.</span></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"margin:0in 0.5in 0in 0in;text-align:center;direction:rtl;unicode-bidi:embe=
d;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-sp=
acing:-0.5pt"><span style=3D"font-size:10pt;font-family:Symbol">=C2=B7<span=
 style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-featu=
re-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;fon=
t-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:22pt;font-family:&quot;Times New Roman&quot;,serif">=D8=AE=D8=B7=D9=88=
=D8=A7=D8=AA =D8=A8=D9=86=D8=A7=D8=A1
=D9=85=D8=AA=D8=AC=D8=B1 =D8=A5=D9=84=D9=83=D8=AA=D8=B1=D9=88=D9=86=D9=8A =
=D8=A7=D8=AD=D8=AA=D8=B1=D8=A7=D9=81=D9=8A =D8=A8=D8=A7=D8=B3=D8=AA=D8=AE=
=D8=AF=D8=A7=D9=85 =D8=A3=D8=AF=D9=88=D8=A7=D8=AA =D9=88=D9=85=D9=86=D8=B5=
=D8=A7=D8=AA =D8=B9=D8=A7=D9=84=D9=85=D9=8A=D8=A9</span><span dir=3D"LTR"><=
/span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:22pt"><=
span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"margin:0in 0.5in 0in 0in;text-align:center;direction:rtl;unicode-bidi:embe=
d;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-sp=
acing:-0.5pt"><span style=3D"font-size:10pt;font-family:Symbol">=C2=B7<span=
 style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-featu=
re-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;fon=
t-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:22pt;font-family:&quot;Times New Roman&quot;,serif">=D8=AA=D8=B5=D9=85=
=D9=8A=D9=85 =D8=AA=D8=AC=D8=B1=D8=A8=D8=A9
=D9=85=D8=B3=D8=AA=D8=AE=D8=AF=D9=85 =D9=85=D8=AA=D9=85=D9=8A=D8=B2=D8=A9 =
=D8=AA=D8=B3=D9=87=D9=91=D9=84 =D8=A7=D9=84=D8=B4=D8=B1=D8=A7=D8=A1 =D9=88=
=D8=AA=D8=B2=D9=8A=D8=AF =D9=85=D9=86 =D9=88=D9=84=D8=A7=D8=A1 =D8=A7=D9=84=
=D8=B9=D9=85=D9=84=D8=A7=D8=A1</span><span dir=3D"LTR"></span><span dir=3D"=
LTR"></span><span dir=3D"LTR" style=3D"font-size:22pt"><span dir=3D"LTR"></=
span><span dir=3D"LTR"></span>.</span></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"margin:0in 0.5in 0in 0in;text-align:center;direction:rtl;unicode-bidi:embe=
d;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-sp=
acing:-0.5pt"><span style=3D"font-size:10pt;font-family:Symbol">=C2=B7<span=
 style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-featu=
re-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;fon=
t-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:22pt;font-family:&quot;Times New Roman&quot;,serif">=D8=AA=D9=86=D9=81=
=D9=8A=D8=B0 =D8=AD=D9=85=D9=84=D8=A7=D8=AA
=D8=AA=D8=B3=D9=88=D9=8A=D9=82 =D8=B1=D9=82=D9=85=D9=8A =D9=81=D8=B9=D9=91=
=D8=A7=D9=84=D8=A9 =D8=A8=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D8=A7=
=D9=84=D8=A5=D8=B9=D9=84=D8=A7=D9=86=D8=A7=D8=AA=D8=8C </span><span dir=3D"=
LTR" style=3D"font-size:22pt">SEO</span><span dir=3D"RTL"></span><span dir=
=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&q=
uot;Times New Roman&quot;,serif"><span dir=3D"RTL"></span><span dir=3D"RTL"=
></span>=D8=8C =D9=88=D9=88=D8=B3=D8=A7=D8=A6=D9=84 =D8=A7=D9=84=D8=AA=D9=
=88=D8=A7=D8=B5=D9=84</span><span dir=3D"LTR"></span><span dir=3D"LTR"></sp=
an><span dir=3D"LTR" style=3D"font-size:22pt"><span dir=3D"LTR"></span><spa=
n dir=3D"LTR"></span>.</span></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"margin:0in 0.5in 0in 0in;text-align:center;direction:rtl;unicode-bidi:embe=
d;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-sp=
acing:-0.5pt"><span style=3D"font-size:10pt;font-family:Symbol">=C2=B7<span=
 style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-featu=
re-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;fon=
t-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:22pt;font-family:&quot;Times New Roman&quot;,serif">=D8=A5=D8=AF=D8=A7=
=D8=B1=D8=A9 =D8=B9=D9=85=D9=84=D9=8A=D8=A7=D8=AA
=D8=A7=D9=84=D8=AF=D9=81=D8=B9=D8=8C =D8=A7=D9=84=D8=AA=D9=88=D8=B5=D9=8A=
=D9=84=D8=8C =D9=88=D8=AE=D8=AF=D9=85=D8=A9 =D8=A7=D9=84=D8=B9=D9=85=D9=84=
=D8=A7=D8=A1 =D8=A8=D8=B4=D9=83=D9=84 =D9=85=D8=AA=D9=83=D8=A7=D9=85=D9=84 =
=D9=88=D8=A7=D8=AD=D8=AA=D8=B1=D8=A7=D9=81=D9=8A</span><span dir=3D"LTR"></=
span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:22pt"><s=
pan dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"margin:0in 0.5in 0in 0in;text-align:center;direction:rtl;unicode-bidi:embe=
d;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-sp=
acing:-0.5pt"><span style=3D"font-size:10pt;font-family:Symbol">=C2=B7<span=
 style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-featu=
re-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;fon=
t-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:22pt;font-family:&quot;Times New Roman&quot;,serif">=D8=AA=D8=AD=D9=84=
=D9=8A=D9=84 =D8=A8=D9=8A=D8=A7=D9=86=D8=A7=D8=AA
=D8=A7=D9=84=D8=B2=D9=88=D8=A7=D8=B1 =D9=88=D8=A7=D9=84=D9=85=D8=A8=D9=8A=
=D8=B9=D8=A7=D8=AA =D9=88=D8=A7=D8=AA=D8=AE=D8=A7=D8=B0 =D9=82=D8=B1=D8=A7=
=D8=B1=D8=A7=D8=AA =D9=85=D8=AF=D8=B1=D9=88=D8=B3=D8=A9 =D9=84=D8=AA=D8=AD=
=D8=B3=D9=8A=D9=86 =D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1</span><span dir=3D"=
LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:2=
2pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"margin:0in 0.5in 0in 0in;text-align:center;direction:rtl;unicode-bidi:embe=
d;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-sp=
acing:-0.5pt"><span style=3D"font-size:10pt;font-family:Symbol">=C2=B7<span=
 style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-featu=
re-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;fon=
t-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:22pt;font-family:&quot;Times New Roman&quot;,serif">=D8=AA=D8=B7=D8=A8=
=D9=8A=D9=82 =D8=A3=D8=AF=D9=88=D8=A7=D8=AA
=D8=A7=D9=84=D8=B0=D9=83=D8=A7=D8=A1 =D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=
=D8=A7=D8=B9=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D8=AA=D8=B3=D9=88=D9=8A=D9=82 =
=D9=88=D8=A7=D9=84=D8=AA=D8=AD=D9=84=D9=8A=D9=84 =D9=88=D8=A7=D9=84=D8=AA=
=D8=AE=D8=B5=D9=8A=D8=B5</span><span dir=3D"LTR"></span><span dir=3D"LTR"><=
/span><span dir=3D"LTR" style=3D"font-size:22pt"><span dir=3D"LTR"></span><=
span dir=3D"LTR"></span>.</span></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"margin:0in 0.5in 0in 0in;text-align:center;direction:rtl;unicode-bidi:embe=
d;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-sp=
acing:-0.5pt"><span style=3D"font-size:10pt;font-family:Symbol">=C2=B7<span=
 style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-featu=
re-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;fon=
t-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:22pt;font-family:&quot;Times New Roman&quot;,serif">=D8=A7=D8=B3=D8=AA=
=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A7=D8=AA
=D8=A7=D9=84=D8=AA=D9=88=D8=B3=D8=B9 =D9=88=D8=A7=D9=84=D9=86=D9=85=D9=88 =
=D9=81=D9=8A =D8=A7=D9=84=D8=B3=D9=88=D9=82 =D8=A7=D9=84=D9=85=D8=AD=D9=84=
=D9=8A =D9=88=D8=A7=D9=84=D8=B9=D8=A7=D9=84=D9=85=D9=8A</span><span dir=3D"=
LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:2=
2pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28=
pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">=
<span dir=3D"LTR" style=3D"font-size:22pt">=C2=A0</span></p>

<p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D"t=
ext-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font-s=
ize:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0=
.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif;color:rgb(192,0,0)">=D8=A3=D9=87=D8=AF=D8=A7=D9=81
=D8=A7=D9=84=D8=A8=D8=B1=D9=86=D8=A7=D9=85=D8=AC</span><span dir=3D"LTR"></=
span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:22pt;col=
or:rgb(192,0,0)"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>:</span>=
</p>

<ul style=3D"margin-top:0in;margin-bottom:0in" type=3D"disc">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-si=
ze:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt=
">=D8=AA=D9=85=D9=83=D9=8A=D9=86
     =D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83=D9=8A=D9=86 =D9=85=D9=86 =
=D9=81=D9=87=D9=85 =D9=86=D9=85=D8=A7=D8=B0=D8=AC =D8=A7=D9=84=D8=AA=D8=AC=
=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=A5=D9=84=D9=83=D8=AA=D8=B1=D9=88=D9=86=
=D9=8A=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span =
dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Calibri Light&quot;,s=
ans-serif;letter-spacing:-0.5pt"><span dir=3D"LTR"></span><span dir=3D"LTR"=
></span> B2B </span><span lang=3D"AR-SA" style=3D"font-size:22pt;font-famil=
y:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt">=D9=88</span><sp=
an dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Calibri Light&quot=
;,sans-serif;letter-spacing:-0.5pt">B2C.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-si=
ze:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt=
">=D8=A8=D9=86=D8=A7=D8=A1
     =D9=88=D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D9=85=D8=AA=D8=A7=D8=AC=D8=B1 =
=D8=A5=D9=84=D9=83=D8=AA=D8=B1=D9=88=D9=86=D9=8A=D8=A9 =D8=A7=D8=AD=D8=AA=
=D8=B1=D8=A7=D9=81=D9=8A=D8=A9 =D8=AA=D8=AA=D9=88=D8=A7=D9=81=D9=82 =D9=85=
=D8=B9 =D8=A7=D8=AD=D8=AA=D9=8A=D8=A7=D8=AC=D8=A7=D8=AA =D8=A7=D9=84=D8=B9=
=D9=85=D9=84=D8=A7=D8=A1 =D9=88=D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D8=A7=
=D8=AA</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D=
"LTR" style=3D"font-size:22pt;font-family:&quot;Calibri Light&quot;,sans-se=
rif;letter-spacing:-0.5pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></spa=
n>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-si=
ze:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt=
">=D8=AA=D8=B7=D8=A8=D9=8A=D9=82
     =D8=A3=D8=AD=D8=AF=D8=AB =D8=A7=D9=84=D8=A3=D8=AF=D9=88=D8=A7=D8=AA =
=D9=88=D8=A7=D9=84=D9=85=D9=86=D8=B5=D8=A7=D8=AA =D9=81=D9=8A =D8=A7=D9=84=
=D8=AA=D8=B3=D9=88=D9=8A=D9=82 =D9=88=D8=A7=D9=84=D8=A8=D9=8A=D8=B9 =D8=A7=
=D9=84=D8=A5=D9=84=D9=83=D8=AA=D8=B1=D9=88=D9=86=D9=8A</span><span dir=3D"L=
TR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:22=
pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">=
<span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-si=
ze:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt=
">=D8=AA=D8=AD=D9=84=D9=8A=D9=84
     =D8=A8=D9=8A=D8=A7=D9=86=D8=A7=D8=AA =D8=A7=D9=84=D8=B2=D8=A8=D8=A7=D8=
=A6=D9=86 =D9=88=D8=AA=D8=AD=D8=B3=D9=8A=D9=86 =D8=AA=D8=AC=D8=B1=D8=A8=D8=
=A9 =D8=A7=D9=84=D9=85=D8=B3=D8=AA=D8=AE=D8=AF=D9=85 =D8=B9=D8=A8=D8=B1 =D8=
=A7=D9=84=D9=82=D9=86=D9=88=D8=A7=D8=AA =D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=
=8A=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=
=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Calibri Light&quot;,sans=
-serif;letter-spacing:-0.5pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></=
span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-si=
ze:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt=
">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9
     =D8=B9=D9=85=D9=84=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D8=AF=D9=81=D8=B9=D8=
=8C =D8=A7=D9=84=D8=B4=D8=AD=D9=86=D8=8C =D9=88=D8=AE=D8=AF=D9=85=D8=A9 =D9=
=85=D8=A7 =D8=A8=D8=B9=D8=AF =D8=A7=D9=84=D8=A8=D9=8A=D8=B9 =D8=A8=D9=81=D8=
=B9=D8=A7=D9=84=D9=8A=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR=
"></span><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Calibr=
i Light&quot;,sans-serif;letter-spacing:-0.5pt"><span dir=3D"LTR"></span><s=
pan dir=3D"LTR"></span>.</span></li>
</ul>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 8pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spaci=
ng:-0.5pt">=C2=A0</span></p>

<p class=3D"gmail-MsoTitle" align=3D"center" dir=3D"RTL" style=3D"text-alig=
n:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font-size:28pt=
;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"><s=
pan lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New Roma=
n&quot;,serif;color:rgb(192,0,0)">=D8=A7=D9=84=D9=85=D8=AD=D8=A7=D9=88=D8=
=B1 =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=D9=8A=D8=A9</span><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-si=
ze:22pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>:</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in;tex=
t-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-siz=
e:11pt;font-family:Calibri,sans-serif"><b><span dir=3D"LTR" style=3D"font-s=
ize:22pt;font-family:&quot;Segoe UI Emoji&quot;,sans-serif;letter-spacing:-=
0.5pt">=F0=9F=94=B9</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt;=
font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">
1. </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&=
quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt">=D9=85=D9=82=D8=AF=
=D9=85=D8=A9
=D9=81=D9=8A =D8=A7=D9=84=D8=AA=D8=AC=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=A5=
=D9=84=D9=83=D8=AA=D8=B1=D9=88=D9=86=D9=8A=D8=A9</span></b><b><span dir=3D"=
LTR" style=3D"font-size:22pt;font-family:&quot;Calibri Light&quot;,sans-ser=
if;letter-spacing:-0.5pt"></span></b></p>

<ul style=3D"margin-top:0in;margin-bottom:0in" type=3D"disc">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=3D"font=
-size:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.=
5pt">=D8=A7=D9=84=D9=81=D8=B1=D9=82
     =D8=A8=D9=8A=D9=86</span></b><span dir=3D"LTR"></span><span dir=3D"LTR=
"></span><b><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Cal=
ibri Light&quot;,sans-serif;letter-spacing:-0.5pt"><span dir=3D"LTR"></span=
><span dir=3D"LTR"></span> B2B </span></b><b><span lang=3D"AR-SA" style=3D"=
font-size:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing=
:-0.5pt">=D9=88</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt;font=
-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">B2C</sp=
an></b></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=3D"font=
-size:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.=
5pt">=D8=A7=D9=84=D8=A7=D8=AA=D8=AC=D8=A7=D9=87=D8=A7=D8=AA
     =D8=A7=D9=84=D8=B9=D8=A7=D9=84=D9=85=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D9=
=85=D8=AD=D9=84=D9=8A=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=AA=D8=AC=D8=A7=D8=
=B1=D8=A9 =D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A=D8=A9</span></b><b><span dir=
=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Calibri Light&quot;,sans=
-serif;letter-spacing:-0.5pt"></span></b></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=3D"font=
-size:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.=
5pt">=D8=B9=D9=86=D8=A7=D8=B5=D8=B1
     =D8=A7=D9=84=D9=86=D8=AC=D8=A7=D8=AD =D9=81=D9=8A =D8=A7=D9=84=D8=A3=
=D8=B9=D9=85=D8=A7=D9=84 =D8=A7=D9=84=D8=A5=D9=84=D9=83=D8=AA=D8=B1=D9=88=
=D9=86=D9=8A=D8=A9</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt;f=
ont-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"></sp=
an></b></li>
</ul>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in;tex=
t-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-siz=
e:11pt;font-family:Calibri,sans-serif"><b><span dir=3D"LTR" style=3D"font-s=
ize:22pt;font-family:&quot;Segoe UI Emoji&quot;,sans-serif;letter-spacing:-=
0.5pt">=F0=9F=94=B9</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt;=
font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">
2. </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&=
quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt">=D8=AA=D8=B5=D9=85=
=D9=8A=D9=85
=D9=88=D8=A5=D8=B7=D9=84=D8=A7=D9=82 =D9=85=D8=AA=D8=AC=D8=B1 =D8=A5=D9=84=
=D9=83=D8=AA=D8=B1=D9=88=D9=86=D9=8A</span></b><b><span dir=3D"LTR" style=
=3D"font-size:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-=
spacing:-0.5pt"></span></b></p>

<ul style=3D"margin-top:0in;margin-bottom:0in" type=3D"disc">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=3D"font=
-size:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.=
5pt">=D8=A7=D8=AE=D8=AA=D9=8A=D8=A7=D8=B1
     =D8=A7=D9=84=D9=85=D9=86=D8=B5=D8=A7=D8=AA =D8=A7=D9=84=D9=85=D9=86=D8=
=A7=D8=B3=D8=A8=D8=A9</span></b><span dir=3D"LTR"></span><span dir=3D"LTR">=
</span><b><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Calib=
ri Light&quot;,sans-serif;letter-spacing:-0.5pt"><span dir=3D"LTR"></span><=
span dir=3D"LTR"></span> (Shopify =E2=80=93 WooCommerce =E2=80=93 Magento)<=
/span></b></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=3D"font=
-size:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.=
5pt">=D8=A5=D8=B9=D8=AF=D8=A7=D8=AF
     =D8=A7=D9=84=D9=85=D9=86=D8=AA=D8=AC=D8=A7=D8=AA =D9=88=D8=A7=D9=84=D8=
=A8=D9=88=D8=A7=D8=A8=D8=A7=D8=AA =D8=A7=D9=84=D8=A5=D9=84=D9=83=D8=AA=D8=
=B1=D9=88=D9=86=D9=8A=D8=A9 =D9=84=D9=84=D8=AF=D9=81=D8=B9</span></b><b><sp=
an dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Calibri Light&quot=
;,sans-serif;letter-spacing:-0.5pt"></span></b></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=3D"font=
-size:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.=
5pt">=D8=AA=D8=AC=D8=B1=D8=A8=D8=A9
     =D8=A7=D9=84=D9=85=D8=B3=D8=AA=D8=AE=D8=AF=D9=85</span></b><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font=
-size:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:=
-0.5pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></span> UX / </span></b>=
<b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New=
 Roman&quot;,serif;letter-spacing:-0.5pt">=D9=88=D8=A7=D8=AC=D9=87=D8=A9 =
=D8=A7=D9=84=D9=85=D8=B3=D8=AA=D8=AE=D8=AF=D9=85</span></b><span dir=3D"LTR=
"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:2=
2pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"=
><span dir=3D"LTR"></span><span dir=3D"LTR"></span> UI</span></b></li>
</ul>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in;tex=
t-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-siz=
e:11pt;font-family:Calibri,sans-serif"><b><span dir=3D"LTR" style=3D"font-s=
ize:22pt;font-family:&quot;Segoe UI Emoji&quot;,sans-serif;letter-spacing:-=
0.5pt">=F0=9F=94=B9</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt;=
font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">
3. </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&=
quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt">=D8=A7=D9=84=D8=AA=
=D8=B3=D9=88=D9=8A=D9=82
=D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A =D9=84=D9=84=D8=AA=D8=AC=D8=A7=D8=B1=
=D8=A9 =D8=A7=D9=84=D8=A5=D9=84=D9=83=D8=AA=D8=B1=D9=88=D9=86=D9=8A=D8=A9</=
span></b><b><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Cal=
ibri Light&quot;,sans-serif;letter-spacing:-0.5pt"></span></b></p>

<ul style=3D"margin-top:0in;margin-bottom:0in" type=3D"disc">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=3D"font=
-size:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.=
5pt">=D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A7=D8=AA
     =D8=A7=D9=84=D8=AA=D8=B3=D9=88=D9=8A=D9=82 =D8=A8=D8=A7=D9=84=D9=85=D8=
=AD=D8=AA=D9=88=D9=89 =D9=88=D8=A7=D9=84=D8=A5=D8=B9=D9=84=D8=A7=D9=86=D8=
=A7=D8=AA =D8=A7=D9=84=D9=85=D9=85=D9=88=D9=84=D8=A9</span></b><b><span dir=
=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Calibri Light&quot;,sans=
-serif;letter-spacing:-0.5pt"></span></b></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=3D"font=
-size:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.=
5pt">=D8=A7=D9=84=D8=AA=D8=B3=D9=88=D9=8A=D9=82
     =D8=B9=D8=A8=D8=B1 =D9=88=D8=B3=D8=A7=D8=A6=D9=84 =D8=A7=D9=84=D8=AA=
=D9=88=D8=A7=D8=B5=D9=84 =D9=88=D9=85=D8=AD=D8=B1=D9=83=D8=A7=D8=AA =D8=A7=
=D9=84=D8=A8=D8=AD=D8=AB</span></b><span dir=3D"LTR"></span><span dir=3D"LT=
R"></span><b><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Ca=
libri Light&quot;,sans-serif;letter-spacing:-0.5pt"><span dir=3D"LTR"></spa=
n><span dir=3D"LTR"></span> SEO/SEM</span></b></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=3D"font=
-size:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.=
5pt">=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85
     =D8=A3=D8=AF=D9=88=D8=A7=D8=AA =D8=A7=D9=84=D8=B0=D9=83=D8=A7=D8=A1 =
=D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=A7=D8=B9=D9=8A =D9=81=D9=8A =D8=A7=
=D9=84=D8=AD=D9=85=D9=84=D8=A7=D8=AA =D8=A7=D9=84=D8=A5=D8=B9=D9=84=D8=A7=
=D9=86=D9=8A=D8=A9</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt;f=
ont-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"></sp=
an></b></li>
</ul>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in;tex=
t-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-siz=
e:11pt;font-family:Calibri,sans-serif"><b><span dir=3D"LTR" style=3D"font-s=
ize:22pt;font-family:&quot;Segoe UI Emoji&quot;,sans-serif;letter-spacing:-=
0.5pt">=F0=9F=94=B9</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt;=
font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">
4. </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&=
quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt">=D8=A5=D8=AF=D8=A7=
=D8=B1=D8=A9
=D8=A7=D9=84=D8=B9=D9=85=D9=84=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D8=A5=D9=84=
=D9=83=D8=AA=D8=B1=D9=88=D9=86=D9=8A=D8=A9</span></b><b><span dir=3D"LTR" s=
tyle=3D"font-size:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"></span></b></p>

<ul style=3D"margin-top:0in;margin-bottom:0in" type=3D"disc">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=3D"font=
-size:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.=
5pt">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9
     =D8=A7=D9=84=D9=85=D8=AE=D8=B2=D9=88=D9=86 =D9=88=D8=B3=D9=84=D8=A7=D8=
=B3=D9=84 =D8=A7=D9=84=D8=A5=D9=85=D8=AF=D8=A7=D8=AF</span></b><b><span dir=
=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Calibri Light&quot;,sans=
-serif;letter-spacing:-0.5pt"></span></b></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=3D"font=
-size:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.=
5pt">=D8=AA=D9=83=D8=A7=D9=85=D9=84
     =D8=A7=D9=84=D8=B4=D8=AD=D9=86 =D9=88=D8=A7=D9=84=D8=AA=D9=88=D8=B5=D9=
=8A=D9=84 =D9=85=D8=B9 =D8=A7=D9=84=D9=85=D8=AA=D8=AC=D8=B1</span></b><b><s=
pan dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Calibri Light&quo=
t;,sans-serif;letter-spacing:-0.5pt"></span></b></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=3D"font=
-size:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.=
5pt">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9
     =D8=B1=D8=B6=D8=A7 =D8=A7=D9=84=D8=B9=D9=85=D9=84=D8=A7=D8=A1 =D9=88=
=D8=AE=D8=AF=D9=85=D8=A9 =D9=85=D8=A7 =D8=A8=D8=B9=D8=AF =D8=A7=D9=84=D8=A8=
=D9=8A=D8=B9</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt;font-fa=
mily:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"></span></b=
></li>
</ul>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in;tex=
t-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-siz=
e:11pt;font-family:Calibri,sans-serif"><b><span dir=3D"LTR" style=3D"font-s=
ize:22pt;font-family:&quot;Segoe UI Emoji&quot;,sans-serif;letter-spacing:-=
0.5pt">=F0=9F=94=B9</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt;=
font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">
5. </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&=
quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt">=D8=AA=D8=AD=D9=84=
=D9=8A=D9=84
=D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1 =D9=88=D8=A7=D9=84=D8=AA=D9=88=D8=B3=
=D8=B9</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&=
quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"></span></b></p>

<ul style=3D"margin-top:0in;margin-bottom:0in" type=3D"disc">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=3D"font=
-size:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.=
5pt">=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85</span></b><span dir=3D"LTR"=
></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:22=
pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">=
<span dir=3D"LTR"></span><span dir=3D"LTR"></span> Google Analytics </span>=
</b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times=
 New Roman&quot;,serif;letter-spacing:-0.5pt">=D9=88</span></b><b><span dir=
=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Calibri Light&quot;,sans=
-serif;letter-spacing:-0.5pt">Meta Business Suite</span></b></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=3D"font=
-size:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.=
5pt">=D8=AA=D9=82=D8=A7=D8=B1=D9=8A=D8=B1
     =D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1 =D9=88=D9=85=D8=A4=D8=B4=D8=B1=D8=
=A7=D8=AA</span></b><span dir=3D"LTR"></span><span dir=3D"LTR"></span><b><s=
pan dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Calibri Light&quo=
t;,sans-serif;letter-spacing:-0.5pt"><span dir=3D"LTR"></span><span dir=3D"=
LTR"></span> KPI</span></b></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=3D"font=
-size:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.=
5pt">=D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A7=D8=AA
     =D8=A7=D9=84=D8=AA=D9=88=D8=B3=D8=B9 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=
=D9=88=D9=82 =D8=A7=D9=84=D9=85=D8=AD=D9=84=D9=8A =D9=88=D8=A7=D9=84=D8=AF=
=D9=88=D9=84=D9=8A</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt;f=
ont-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"></sp=
an></b></li>
</ul>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 8pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spaci=
ng:-0.5pt">=C2=A0</span></p>

<p class=3D"gmail-MsoTitle" align=3D"center" dir=3D"RTL" style=3D"text-alig=
n:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font-size:28pt=
;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"><s=
pan lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New Roma=
n&quot;,serif;color:rgb(192,0,0)">=D8=A7=D9=84=D9=81=D8=A6=D8=A9 =D8=A7=D9=
=84=D9=85=D8=B3=D8=AA=D9=87=D8=AF=D9=81=D8=A9</span><span dir=3D"LTR"></spa=
n><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:22pt;color:=
rgb(192,0,0)"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>:</span></p=
>

<ul style=3D"margin-top:0in;margin-bottom:0in" type=3D"disc">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-si=
ze:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt=
">=D8=B1=D9=88=D8=A7=D8=AF
     =D8=A7=D9=84=D8=A3=D8=B9=D9=85=D8=A7=D9=84 =D9=88=D8=A3=D8=B5=D8=AD=D8=
=A7=D8=A8 =D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=8A=D8=B9 =D8=A7=D9=84=D8=
=A5=D9=84=D9=83=D8=AA=D8=B1=D9=88=D9=86=D9=8A=D8=A9</span><span dir=3D"LTR"=
 style=3D"font-size:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;l=
etter-spacing:-0.5pt"></span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-si=
ze:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt=
">=D9=81=D8=B1=D9=82
     =D8=A7=D9=84=D8=AA=D8=B3=D9=88=D9=8A=D9=82 =D9=88=D8=A7=D9=84=D9=85=D8=
=A8=D9=8A=D8=B9=D8=A7=D8=AA</span><span dir=3D"LTR" style=3D"font-size:22pt=
;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"></=
span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-si=
ze:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt=
">=D9=85=D8=AF=D8=B1=D8=A7=D8=A1
     =D8=A7=D9=84=D8=AA=D8=AC=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=A5=D9=84=D9=
=83=D8=AA=D8=B1=D9=88=D9=86=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=AA=D8=AD=D9=
=88=D9=84 =D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A</span><span dir=3D"LTR" styl=
e=3D"font-size:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter=
-spacing:-0.5pt"></span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-si=
ze:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt=
">=D8=A3=D9=8A
     =D8=B4=D8=AE=D8=B5 =D9=8A=D8=B7=D9=85=D8=AD =D9=84=D8=AF=D8=AE=D9=88=
=D9=84 =D8=B9=D8=A7=D9=84=D9=85 =D8=A7=D9=84=D8=A8=D9=8A=D8=B9 =D8=B9=D8=A8=
=D8=B1 =D8=A7=D9=84=D8=A5=D9=86=D8=AA=D8=B1=D9=86=D8=AA</span><span dir=3D"=
LTR" style=3D"font-size:22pt;font-family:&quot;Calibri Light&quot;,sans-ser=
if;letter-spacing:-0.5pt"></span></li>
</ul>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 8pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spaci=
ng:-0.5pt">=C2=A0</span></p>

<p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=3D"=
text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28p=
t;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"><=
b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New =
Roman&quot;,serif">=D8=B4=D9=87=D8=A7=D8=AF=D8=A7=D8=AA =D9=85=D8=B9=D8=AA=
=D9=85=D8=AF=D8=A9
=D8=AF=D9=88=D9=84=D9=8A=D8=A7 =D9=88=D9=85=D8=AD=D9=84=D9=8A=D8=A7 =D9=85=
=D9=86 =D9=88=D8=B2=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=AE=D8=A7=D8=B1=D8=AC=
=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=B3=D9=81=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=
=D9=82=D9=86=D8=B5=D9=84=D9=8A=D8=A9</span></b></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28=
pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">=
<b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New=
 Roman&quot;,serif">=D9=85=D8=B9=D8=AA=D9=85=D8=AF /=C2=A0</span></b><b><sp=
an dir=3D"LTR" style=3D"font-size:22pt">AHAD</span></b><b><span lang=3D"AR-=
SA" style=3D"font-size:22pt;font-family:&quot;Times New Roman&quot;,serif">=
</span></b></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28=
pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">=
<b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New=
 Roman&quot;,serif">=D8=AA=D9=82=D8=AF=D9=85=D8=A9 =D8=A7=D9=84=D8=AF=D8=A7=
=D8=B1
=D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=
=D9=8A=D8=A9 =D8=A7=D9=84=D8=A7=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9</span></b></p=
>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28=
pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">=
<b><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Segoe UI Emo=
ji&quot;,sans-serif">=F0=9F=93=8A</span></b><b><span dir=3D"LTR" style=3D"f=
ont-size:22pt"> </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;=
font-family:&quot;Times New Roman&quot;,serif">=D8=AC=D8=AF=D9=88=D9=84 =D8=
=A7=D9=84=D8=AF=D9=88=D8=B1=D8=A7=D8=AA
=D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D9=85=D8=AD=
=D8=A7=D8=B3=D8=A8=D9=8A=D8=A9</span></b><b><span dir=3D"LTR" style=3D"font=
-size:22pt"></span></b></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28=
pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">=
<b><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Segoe UI Emo=
ji&quot;,sans-serif">=F0=9F=97=93=EF=B8=8F</span></b><b><span dir=3D"LTR" s=
tyle=3D"font-size:22pt"> </span></b><b><span lang=3D"AR-SA" style=3D"font-s=
ize:22pt;font-family:&quot;Times New Roman&quot;,serif">=D9=85=D9=86 =D8=B3=
=D8=A8=D8=AA=D9=85=D8=A8=D8=B1 =D8=A5=D9=84=D9=89
=D8=AF=D9=8A=D8=B3=D9=85=D8=A8=D8=B1 2025</span></b><b><span dir=3D"LTR" st=
yle=3D"font-size:22pt"><br>
</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;S=
egoe UI Emoji&quot;,sans-serif">=F0=9F=8E=93</span></b><b><span dir=3D"LTR"=
 style=3D"font-size:22pt"> </span></b><b><span lang=3D"AR-SA" style=3D"font=
-size:22pt;font-family:&quot;Times New Roman&quot;,serif">=D9=85=D9=82=D8=
=AF=D9=85=D8=A9 =D9=85=D9=86 =D8=A7=D9=84=D8=AF=D8=A7=D8=B1
=D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=
=D9=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9</span></b><b>=
<span dir=3D"LTR" style=3D"font-size:22pt"><br>
</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;S=
egoe UI Emoji&quot;,sans-serif">=F0=9F=93=8D</span></b><b><span dir=3D"LTR"=
 style=3D"font-size:22pt"> </span></b><b><span lang=3D"AR-SA" style=3D"font=
-size:22pt;font-family:&quot;Times New Roman&quot;,serif">=D8=AF=D8=A8=D9=
=8A =E2=80=93 =D8=A5=D8=B3=D8=B7=D9=86=D8=A8=D9=88=D9=84
=E2=80=93 =D9=85=D8=A7=D9=84=D9=8A=D8=B2=D9=8A=D8=A7</span></b><b><span dir=
=3D"LTR" style=3D"font-size:22pt"><br>
</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;S=
egoe UI Emoji&quot;,sans-serif">=F0=9F=93=9C</span></b><b><span dir=3D"LTR"=
 style=3D"font-size:22pt"> </span></b><b><span lang=3D"AR-SA" style=3D"font=
-size:22pt;font-family:&quot;Times New Roman&quot;,serif">=D8=B4=D9=87=D8=
=A7=D8=AF=D8=A7=D8=AA =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9
=D9=82=D8=A7=D8=A8=D9=84=D8=A9 =D9=84=D9=84=D8=AA=D8=B5=D8=AF=D9=8A=D9=82 =
=D9=85=D9=86 =D9=83=D8=A7=D9=81=D8=A9 =D8=A7=D9=84=D8=B3=D9=81=D8=A7=D8=B1=
=D8=A7=D8=AA =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9</span></b><b><span =
dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>

<div class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span dir=3D"LTR" style=3D"font-size:22pt">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></b></div>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28=
pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">=
<b><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Segoe UI Emo=
ji&quot;,sans-serif">=E2=9C=85</span></b><b><span dir=3D"LTR" style=3D"font=
-size:22pt"> </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;fon=
t-family:&quot;Times New Roman&quot;,serif">=D8=B3=D8=A8=D8=AA=D9=85=D8=A8=
=D8=B1 2025</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span>=
</b></p>

<table class=3D"gmail-MsoNormalTable" border=3D"0" cellpadding=3D"0">
 <thead>
  <tr>
   <td style=3D"border:1pt solid windowtext;padding:0.75pt">
   <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A7=D9=84=D8=AF=D9=88=D8=B1=D8=A9</span></b><b><s=
pan dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
   </td>
   <td style=3D"border:1pt solid windowtext;padding:0.75pt">
   <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A7=D9=84=D9=85=D9=83=D8=A7=D9=86</span></b><b><s=
pan dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
   </td>
   <td style=3D"border:1pt solid windowtext;padding:0.75pt">
   <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A7=D9=84=D8=AA=D8=A7=D8=B1=D9=8A=D8=AE</span></b=
><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
   </td>
   <td style=3D"border:1pt solid windowtext;padding:0.75pt">
   <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;f=
ont-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spaci=
ng:-0.5pt"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quo=
t;Times New Roman&quot;,serif">=D8=A7=D9=84=D8=B1=D8=B3=D9=88=D9=85</span><=
/b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
   </td>
  </tr>
 </thead>
 <tbody><tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A7=D9=84=D8=AA=D8=AD=D9=84=D9=8A=D9=84
  =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A =D9=88=D8=AA=D9=82=D9=8A=D9=8A=D9=85=
 =D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1 =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=
=D9=8A</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b><=
/p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A5=D8=B3=D8=B7=D9=86=D8=A8=D9=88=D9=84</span></b=
><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span dir=3D"LTR" style=3D"font-size:22pt">7
  =E2=80=93 11 </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;f=
ont-family:&quot;Times New Roman&quot;,serif">=D8=B3=D8=A8=D8=AA=D9=85=D8=
=A8=D8=B1</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></=
b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font=
-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:=
-0.5pt"><b><span dir=3D"LTR" style=3D"font-size:22pt">1,400
  </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&q=
uot;Times New Roman&quot;,serif">=D8=AF=D9=88=D9=84=D8=A7=D8=B1</span></b><=
b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A5=D8=B9=D8=AF=D8=A7=D8=AF
  =D8=A7=D9=84=D9=85=D9=88=D8=A7=D8=B2=D9=86=D8=A7=D8=AA =D9=88=D8=A7=D9=84=
=D8=AA=D8=AD=D9=83=D9=85 =D9=81=D9=8A =D8=A7=D9=84=D8=AA=D9=83=D8=A7=D9=84=
=D9=8A=D9=81</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span=
></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=AF=D8=A8=D9=8A</span></b><b><span dir=3D"LTR" st=
yle=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span dir=3D"LTR" style=3D"font-size:22pt">14
  =E2=80=93 18 </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;f=
ont-family:&quot;Times New Roman&quot;,serif">=D8=B3=D8=A8=D8=AA=D9=85=D8=
=A8=D8=B1</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></=
b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font=
-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:=
-0.5pt"><span dir=3D"RTL"></span><span dir=3D"RTL"></span><b><span lang=3D"=
AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New Roman&quot;,seri=
f"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>1750</span></b><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span><b><span lang=3D"AR-SA" dir=3D"L=
TR" style=3D"font-size:22pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></s=
pan> </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family=
:&quot;Times New Roman&quot;,serif">=D8=AF=D9=88=D9=84=D8=A7=D8=B1</span></=
b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A7=D9=84=D9=85=D8=AD=D8=A7=D8=B3=D8=A8=D8=A9
  =D8=A7=D9=84=D8=AD=D9=83=D9=88=D9=85=D9=8A=D8=A9 =D9=88=D9=81=D9=82</span=
></b><span dir=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR"=
 style=3D"font-size:22pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></span=
>
  IPSAS</span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=AF=D8=A8=D9=8A</span></b><b><span dir=3D"LTR" st=
yle=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span dir=3D"LTR" style=3D"font-size:22pt">21
  =E2=80=93 25 </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;f=
ont-family:&quot;Times New Roman&quot;,serif">=D8=B3=D8=A8=D8=AA=D9=85=D8=
=A8=D8=B1</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></=
b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font=
-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:=
-0.5pt"><span dir=3D"RTL"></span><span dir=3D"RTL"></span><b><span lang=3D"=
AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New Roman&quot;,seri=
f"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>1750</span></b><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span><b><span lang=3D"AR-SA" dir=3D"L=
TR" style=3D"font-size:22pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></s=
pan> </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family=
:&quot;Times New Roman&quot;,serif">=D8=AF=D9=88=D9=84=D8=A7=D8=B1</span></=
b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D9=85=D8=AD=D8=A7=D8=B3=D8=A8=D8=A9
  =D8=A7=D9=84=D8=AA=D9=83=D8=A7=D9=84=D9=8A=D9=81 =D9=88=D8=AA=D8=AD=D9=84=
=D9=8A=D9=84 =D8=A7=D9=84=D8=A7=D9=86=D8=AD=D8=B1=D8=A7=D9=81=D8=A7=D8=AA</=
span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A5=D8=B3=D8=B7=D9=86=D8=A8=D9=88=D9=84</span></b=
><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span dir=3D"LTR" style=3D"font-size:22pt">21
  =E2=80=93 25 </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;f=
ont-family:&quot;Times New Roman&quot;,serif">=D8=B3=D8=A8=D8=AA=D9=85=D8=
=A8=D8=B1</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></=
b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font=
-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:=
-0.5pt"><b><span dir=3D"LTR" style=3D"font-size:22pt">1,400
  </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&q=
uot;Times New Roman&quot;,serif">=D8=AF=D9=88=D9=84=D8=A7=D8=B1</span></b><=
b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A7=D9=84=D8=A3=D8=B3=D8=B3
  =D8=A7=D9=84=D8=AD=D8=AF=D9=8A=D8=AB=D8=A9 =D9=81=D9=8A =D8=A5=D8=B9=D8=
=AF=D8=A7=D8=AF =D8=A7=D9=84=D8=AA=D9=82=D8=A7=D8=B1=D9=8A=D8=B1 =D8=A7=D9=
=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9</span></b><b><span dir=3D"LTR" style=3D"f=
ont-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D9=85=D8=A7=D9=84=D9=8A=D8=B2=D9=8A=D8=A7</span></b=
><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span dir=3D"LTR" style=3D"font-size:22pt">28
  </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&q=
uot;Times New Roman&quot;,serif">=D8=B3=D8=A8=D8=AA=D9=85=D8=A8=D8=B1 =E2=
=80=93 2 =D8=A3=D9=83=D8=AA=D9=88=D8=A8=D8=B1</span></b><b><span dir=3D"LTR=
" style=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font=
-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:=
-0.5pt"><span dir=3D"RTL"></span><span dir=3D"RTL"></span><b><span lang=3D"=
AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New Roman&quot;,seri=
f"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>2000</span></b><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span><b><span lang=3D"AR-SA" dir=3D"L=
TR" style=3D"font-size:22pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></s=
pan> </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family=
:&quot;Times New Roman&quot;,serif">=D8=AF=D9=88=D9=84=D8=A7=D8=B1</span></=
b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A7=D9=84=D8=AA=D8=AD=D9=84=D9=8A=D9=84
  =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A =D8=A8=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=
=D8=A7=D9=85</span></b><span dir=3D"LTR"></span><span dir=3D"LTR"></span><b=
><span dir=3D"LTR" style=3D"font-size:22pt"><span dir=3D"LTR"></span><span =
dir=3D"LTR"></span>
  Excel</span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=AF=D8=A8=D9=8A</span></b><b><span dir=3D"LTR" st=
yle=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span dir=3D"LTR" style=3D"font-size:22pt">28
  </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&q=
uot;Times New Roman&quot;,serif">=D8=B3=D8=A8=D8=AA=D9=85=D8=A8=D8=B1 =E2=
=80=93 2 =D8=A3=D9=83=D8=AA=D9=88=D8=A8=D8=B1</span></b><b><span dir=3D"LTR=
" style=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font=
-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:=
-0.5pt"><span dir=3D"RTL"></span><span dir=3D"RTL"></span><b><span lang=3D"=
AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New Roman&quot;,seri=
f"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>1750</span></b><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span><b><span lang=3D"AR-SA" dir=3D"L=
TR" style=3D"font-size:22pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></s=
pan> </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family=
:&quot;Times New Roman&quot;,serif">=D8=AF=D9=88=D9=84=D8=A7=D8=B1</span></=
b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
 </tr>
</tbody></table>

<div class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span dir=3D"LTR" style=3D"font-size:22pt">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></b></div>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28=
pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">=
<b><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Segoe UI Emo=
ji&quot;,sans-serif">=E2=9C=85</span></b><b><span dir=3D"LTR" style=3D"font=
-size:22pt"> </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;fon=
t-family:&quot;Times New Roman&quot;,serif">=D8=A3=D9=83=D8=AA=D9=88=D8=A8=
=D8=B1 2025</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span>=
</b></p>

<table class=3D"gmail-MsoNormalTable" border=3D"0" cellpadding=3D"0">
 <thead>
  <tr>
   <td style=3D"border:1pt solid windowtext;padding:0.75pt">
   <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A7=D9=84=D8=AF=D9=88=D8=B1=D8=A9</span></b><b><s=
pan dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
   </td>
   <td style=3D"border:1pt solid windowtext;padding:0.75pt">
   <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A7=D9=84=D9=85=D9=83=D8=A7=D9=86</span></b><b><s=
pan dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
   </td>
   <td style=3D"border:1pt solid windowtext;padding:0.75pt">
   <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A7=D9=84=D8=AA=D8=A7=D8=B1=D9=8A=D8=AE</span></b=
><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
   </td>
   <td style=3D"border:1pt solid windowtext;padding:0.75pt">
   <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;f=
ont-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spaci=
ng:-0.5pt"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quo=
t;Times New Roman&quot;,serif">=D8=A7=D9=84=D8=B1=D8=B3=D9=88=D9=85</span><=
/b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
   </td>
  </tr>
 </thead>
 <tbody><tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A7=D9=84=D9=85=D8=AD=D8=A7=D8=B3=D8=A8=D8=A9
  =D9=88=D8=A7=D9=84=D8=A7=D8=AA=D8=B5=D8=A7=D9=84 =D8=A7=D9=84=D9=85=D8=A7=
=D9=84=D9=8A =D9=88=D8=A7=D8=AA=D8=AE=D8=A7=D8=B0 =D8=A7=D9=84=D9=82=D8=B1=
=D8=A7=D8=B1</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span=
></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=AF=D8=A8=D9=8A</span></b><b><span dir=3D"LTR" st=
yle=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span dir=3D"LTR" style=3D"font-size:22pt">5
  =E2=80=93 9 </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;fo=
nt-family:&quot;Times New Roman&quot;,serif">=D8=A3=D9=83=D8=AA=D9=88=D8=A8=
=D8=B1</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b><=
/p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font=
-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:=
-0.5pt"><span dir=3D"RTL"></span><span dir=3D"RTL"></span><b><span lang=3D"=
AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New Roman&quot;,seri=
f"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>1750</span></b><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span><b><span lang=3D"AR-SA" dir=3D"L=
TR" style=3D"font-size:22pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></s=
pan> </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family=
:&quot;Times New Roman&quot;,serif">=D8=AF=D9=88=D9=84=D8=A7=D8=B1</span></=
b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A7=D9=84=D9=85=D8=B1=D8=A7=D8=AC=D8=B9=D8=A9
  =D9=88=D8=A7=D9=84=D8=AA=D8=AF=D9=82=D9=8A=D9=82 =D8=A7=D9=84=D9=85=D8=A7=
=D9=84=D9=8A =D9=88=D8=A7=D9=84=D8=B6=D8=B1=D9=8A=D8=A8=D9=8A</span></b><b>=
<span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A5=D8=B3=D8=B7=D9=86=D8=A8=D9=88=D9=84</span></b=
><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span dir=3D"LTR" style=3D"font-size:22pt">5
  =E2=80=93 9 </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;fo=
nt-family:&quot;Times New Roman&quot;,serif">=D8=A3=D9=83=D8=AA=D9=88=D8=A8=
=D8=B1</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b><=
/p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font=
-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:=
-0.5pt"><b><span dir=3D"LTR" style=3D"font-size:22pt">1,400
  </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&q=
uot;Times New Roman&quot;,serif">=D8=AF=D9=88=D9=84=D8=A7=D8=B1</span></b><=
b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A7=D9=84=D9=85=D8=AD=D8=A7=D8=B3=D8=A8=D8=A9
  =D8=A7=D9=84=D8=AD=D9=83=D9=88=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D8=AA=
=D9=82=D8=AF=D9=85=D8=A9</span></b><b><span dir=3D"LTR" style=3D"font-size:=
22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D9=85=D8=A7=D9=84=D9=8A=D8=B2=D9=8A=D8=A7</span></b=
><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span dir=3D"LTR" style=3D"font-size:22pt">12
  =E2=80=93 16 </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;f=
ont-family:&quot;Times New Roman&quot;,serif">=D8=A3=D9=83=D8=AA=D9=88=D8=
=A8=D8=B1</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></=
b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font=
-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:=
-0.5pt"><span dir=3D"RTL"></span><span dir=3D"RTL"></span><b><span lang=3D"=
AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New Roman&quot;,seri=
f"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>2000</span></b><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span><b><span lang=3D"AR-SA" dir=3D"L=
TR" style=3D"font-size:22pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></s=
pan> </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family=
:&quot;Times New Roman&quot;,serif">=D8=AF=D9=88=D9=84=D8=A7=D8=B1</span></=
b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A5=D8=B9=D8=AF=D8=A7=D8=AF
  =D8=A7=D9=84=D8=AD=D8=B3=D8=A7=D8=A8=D8=A7=D8=AA =D8=A7=D9=84=D8=AE=D8=AA=
=D8=A7=D9=85=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=AA=D8=B3=D9=88=D9=8A=D8=A7=
=D8=AA =D8=A7=D9=84=D8=AC=D8=B1=D8=AF=D9=8A=D8=A9</span></b><b><span dir=3D=
"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=AF=D8=A8=D9=8A</span></b><b><span dir=3D"LTR" st=
yle=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span dir=3D"LTR" style=3D"font-size:22pt">19
  =E2=80=93 23 </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;f=
ont-family:&quot;Times New Roman&quot;,serif">=D8=A3=D9=83=D8=AA=D9=88=D8=
=A8=D8=B1</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></=
b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font=
-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:=
-0.5pt"><span dir=3D"RTL"></span><span dir=3D"RTL"></span><b><span lang=3D"=
AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New Roman&quot;,seri=
f"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>1750</span></b><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span><b><span lang=3D"AR-SA" dir=3D"L=
TR" style=3D"font-size:22pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></s=
pan> </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family=
:&quot;Times New Roman&quot;,serif">=D8=AF=D9=88=D9=84=D8=A7=D8=B1</span></=
b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A5=D8=B9=D8=AF=D8=A7=D8=AF
  =D8=A7=D9=84=D9=82=D9=88=D8=A7=D8=A6=D9=85 =D8=A7=D9=84=D9=85=D8=A7=D9=84=
=D9=8A=D8=A9 =D9=88=D9=81=D9=82</span></b><span dir=3D"LTR"></span><span di=
r=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:22pt"><span dir=3D=
"LTR"></span><span dir=3D"LTR"></span>
  IFRS</span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A5=D8=B3=D8=B7=D9=86=D8=A8=D9=88=D9=84</span></b=
><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span dir=3D"LTR" style=3D"font-size:22pt">19
  =E2=80=93 23 </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;f=
ont-family:&quot;Times New Roman&quot;,serif">=D8=A3=D9=83=D8=AA=D9=88=D8=
=A8=D8=B1</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></=
b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font=
-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:=
-0.5pt"><b><span dir=3D"LTR" style=3D"font-size:22pt">1,400
  </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&q=
uot;Times New Roman&quot;,serif">=D8=AF=D9=88=D9=84=D8=A7=D8=B1</span></b><=
b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=AA=D8=AE=D8=B7=D9=8A=D8=B7
  =D8=A7=D9=84=D9=85=D9=88=D8=A7=D8=B2=D9=86=D8=A7=D8=AA =D9=88=D8=B1=D9=82=
=D8=A7=D8=A8=D8=A9 =D8=A7=D9=84=D8=AA=D9=83=D8=A7=D9=84=D9=8A=D9=81</span><=
/b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=AF=D8=A8=D9=8A</span></b><b><span dir=3D"LTR" st=
yle=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span dir=3D"LTR" style=3D"font-size:22pt">26
  =E2=80=93 30 </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;f=
ont-family:&quot;Times New Roman&quot;,serif">=D8=A3=D9=83=D8=AA=D9=88=D8=
=A8=D8=B1</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></=
b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font=
-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:=
-0.5pt"><span dir=3D"RTL"></span><span dir=3D"RTL"></span><b><span lang=3D"=
AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New Roman&quot;,seri=
f"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>1750</span></b><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span><b><span lang=3D"AR-SA" dir=3D"L=
TR" style=3D"font-size:22pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></s=
pan> </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family=
:&quot;Times New Roman&quot;,serif">=D8=AF=D9=88=D9=84=D8=A7=D8=B1</span></=
b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
 </tr>
</tbody></table>

<div class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span dir=3D"LTR" style=3D"font-size:22pt">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></b></div>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28=
pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">=
<b><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Segoe UI Emo=
ji&quot;,sans-serif">=E2=9C=85</span></b><b><span dir=3D"LTR" style=3D"font=
-size:22pt"> </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;fon=
t-family:&quot;Times New Roman&quot;,serif">=D9=86=D9=88=D9=81=D9=85=D8=A8=
=D8=B1 2025</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span>=
</b></p>

<table class=3D"gmail-MsoNormalTable" border=3D"0" cellpadding=3D"0">
 <thead>
  <tr>
   <td style=3D"border:1pt solid windowtext;padding:0.75pt">
   <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A7=D9=84=D8=AF=D9=88=D8=B1=D8=A9</span></b><b><s=
pan dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
   </td>
   <td style=3D"border:1pt solid windowtext;padding:0.75pt">
   <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A7=D9=84=D9=85=D9=83=D8=A7=D9=86</span></b><b><s=
pan dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
   </td>
   <td style=3D"border:1pt solid windowtext;padding:0.75pt">
   <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A7=D9=84=D8=AA=D8=A7=D8=B1=D9=8A=D8=AE</span></b=
><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
   </td>
   <td style=3D"border:1pt solid windowtext;padding:0.75pt">
   <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;f=
ont-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spaci=
ng:-0.5pt"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quo=
t;Times New Roman&quot;,serif">=D8=A7=D9=84=D8=B1=D8=B3=D9=88=D9=85</span><=
/b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
   </td>
  </tr>
 </thead>
 <tbody><tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A7=D9=84=D9=86=D9=85=D8=B0=D8=AC=D8=A9
  =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9 =D8=A8=D8=A7=D8=B3=D8=AA=D8=AE=
=D8=AF=D8=A7=D9=85</span></b><span dir=3D"LTR"></span><span dir=3D"LTR"></s=
pan><b><span dir=3D"LTR" style=3D"font-size:22pt"><span dir=3D"LTR"></span>=
<span dir=3D"LTR"></span>
  Excel </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-fam=
ily:&quot;Times New Roman&quot;,serif">=D9=88</span></b><b><span dir=3D"LTR=
" style=3D"font-size:22pt">Power BI</span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A5=D8=B3=D8=B7=D9=86=D8=A8=D9=88=D9=84</span></b=
><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span dir=3D"LTR" style=3D"font-size:22pt">2
  =E2=80=93 6 </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;fo=
nt-family:&quot;Times New Roman&quot;,serif">=D9=86=D9=88=D9=81=D9=85=D8=A8=
=D8=B1</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b><=
/p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font=
-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:=
-0.5pt"><b><span dir=3D"LTR" style=3D"font-size:22pt">1,400
  </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&q=
uot;Times New Roman&quot;,serif">=D8=AF=D9=88=D9=84=D8=A7=D8=B1</span></b><=
b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9
  =D9=88=D9=85=D8=AD=D8=A7=D8=B3=D8=A8=D8=A9 =D8=A7=D9=84=D8=A3=D8=B5=D9=88=
=D9=84 =D8=A7=D9=84=D8=AB=D8=A7=D8=A8=D8=AA=D8=A9</span></b><b><span dir=3D=
"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=AF=D8=A8=D9=8A</span></b><b><span dir=3D"LTR" st=
yle=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span dir=3D"LTR" style=3D"font-size:22pt">2
  =E2=80=93 6 </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;fo=
nt-family:&quot;Times New Roman&quot;,serif">=D9=86=D9=88=D9=81=D9=85=D8=A8=
=D8=B1</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b><=
/p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font=
-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:=
-0.5pt"><span dir=3D"RTL"></span><span dir=3D"RTL"></span><b><span lang=3D"=
AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New Roman&quot;,seri=
f"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>1750</span></b><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span><b><span lang=3D"AR-SA" dir=3D"L=
TR" style=3D"font-size:22pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></s=
pan> </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family=
:&quot;Times New Roman&quot;,serif">=D8=AF=D9=88=D9=84=D8=A7=D8=B1</span></=
b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A7=D9=84=D8=AA=D8=AD=D9=84=D9=8A=D9=84
  =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A =D8=A7=D9=84=D9=85=D8=AA=D9=82=D8=AF=
=D9=85</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b><=
/p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D9=85=D8=A7=D9=84=D9=8A=D8=B2=D9=8A=D8=A7</span></b=
><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span dir=3D"LTR" style=3D"font-size:22pt">9
  =E2=80=93 13 </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;f=
ont-family:&quot;Times New Roman&quot;,serif">=D9=86=D9=88=D9=81=D9=85=D8=
=A8=D8=B1</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></=
b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font=
-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:=
-0.5pt"><span dir=3D"RTL"></span><span dir=3D"RTL"></span><b><span lang=3D"=
AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New Roman&quot;,seri=
f"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>2000</span></b><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span><b><span lang=3D"AR-SA" dir=3D"L=
TR" style=3D"font-size:22pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></s=
pan> </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family=
:&quot;Times New Roman&quot;,serif">=D8=AF=D9=88=D9=84=D8=A7=D8=B1</span></=
b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A5=D8=B9=D8=AF=D8=A7=D8=AF =D8=AF=D8=B1=D8=A7=D8=
=B3=D8=A7=D8=AA
  =D8=A7=D9=84=D8=AC=D8=AF=D9=88=D9=89 =D9=88=D8=A7=D9=84=D8=AA=D9=85=D9=88=
=D9=8A=D9=84 =D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=
=D9=8A</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b><=
/p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=AF=D8=A8=D9=8A</span></b><b><span dir=3D"LTR" st=
yle=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span dir=3D"LTR" style=3D"font-size:22pt">16
  =E2=80=93 20 </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;f=
ont-family:&quot;Times New Roman&quot;,serif">=D9=86=D9=88=D9=81=D9=85=D8=
=A8=D8=B1</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></=
b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font=
-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:=
-0.5pt"><span dir=3D"RTL"></span><span dir=3D"RTL"></span><b><span lang=3D"=
AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New Roman&quot;,seri=
f"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>1750</span></b><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span><b><span lang=3D"AR-SA" dir=3D"L=
TR" style=3D"font-size:22pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></s=
pan> </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family=
:&quot;Times New Roman&quot;,serif">=D8=AF=D9=88=D9=84=D8=A7=D8=B1</span></=
b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D9=85=D8=B1=D8=A7=D9=82=D8=A8=D8=A9
  =D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=
 =D9=88=D8=AA=D9=82=D8=A7=D8=B1=D9=8A=D8=B1 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=
=D8=B1=D8=A9</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span=
></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A5=D8=B3=D8=B7=D9=86=D8=A8=D9=88=D9=84</span></b=
><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span dir=3D"LTR" style=3D"font-size:22pt">23
  =E2=80=93 27 </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;f=
ont-family:&quot;Times New Roman&quot;,serif">=D9=86=D9=88=D9=81=D9=85=D8=
=A8=D8=B1</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></=
b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font=
-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:=
-0.5pt"><b><span dir=3D"LTR" style=3D"font-size:22pt">1,400
  </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&q=
uot;Times New Roman&quot;,serif">=D8=AF=D9=88=D9=84=D8=A7=D8=B1</span></b><=
b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A7=D9=84=D8=B1=D9=82=D8=A7=D8=A8=D8=A9
  =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=A7=D9=85=
=D8=AA=D8=AB=D8=A7=D9=84 =D9=84=D9=84=D9=85=D9=88=D8=A7=D8=B2=D9=86=D8=A7=
=D8=AA</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b><=
/p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=AF=D8=A8=D9=8A</span></b><b><span dir=3D"LTR" st=
yle=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span dir=3D"LTR" style=3D"font-size:22pt">23
  =E2=80=93 27 </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;f=
ont-family:&quot;Times New Roman&quot;,serif">=D9=86=D9=88=D9=81=D9=85=D8=
=A8=D8=B1</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></=
b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font=
-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:=
-0.5pt"><span dir=3D"RTL"></span><span dir=3D"RTL"></span><b><span lang=3D"=
AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New Roman&quot;,seri=
f"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>1750</span></b><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span><b><span lang=3D"AR-SA" dir=3D"L=
TR" style=3D"font-size:22pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></s=
pan> </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family=
:&quot;Times New Roman&quot;,serif">=D8=AF=D9=88=D9=84=D8=A7=D8=B1</span></=
b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
 </tr>
</tbody></table>

<div class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span dir=3D"LTR" style=3D"font-size:22pt">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></b></div>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28=
pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">=
<b><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Segoe UI Emo=
ji&quot;,sans-serif">=E2=9C=85</span></b><b><span dir=3D"LTR" style=3D"font=
-size:22pt"> </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;fon=
t-family:&quot;Times New Roman&quot;,serif">=D8=AF=D9=8A=D8=B3=D9=85=D8=A8=
=D8=B1 2025</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span>=
</b></p>

<table class=3D"gmail-MsoNormalTable" border=3D"0" cellpadding=3D"0">
 <thead>
  <tr>
   <td style=3D"border:1pt solid windowtext;padding:0.75pt">
   <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A7=D9=84=D8=AF=D9=88=D8=B1=D8=A9</span></b><b><s=
pan dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
   </td>
   <td style=3D"border:1pt solid windowtext;padding:0.75pt">
   <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A7=D9=84=D9=85=D9=83=D8=A7=D9=86</span></b><b><s=
pan dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
   </td>
   <td style=3D"border:1pt solid windowtext;padding:0.75pt">
   <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A7=D9=84=D8=AA=D8=A7=D8=B1=D9=8A=D8=AE</span></b=
><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
   </td>
   <td style=3D"border:1pt solid windowtext;padding:0.75pt">
   <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;f=
ont-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spaci=
ng:-0.5pt"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quo=
t;Times New Roman&quot;,serif">=D8=A7=D9=84=D8=B1=D8=B3=D9=88=D9=85</span><=
/b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
   </td>
  </tr>
 </thead>
 <tbody><tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A5=D8=B9=D8=AF=D8=A7=D8=AF
  =D8=A7=D9=84=D8=AA=D9=82=D8=A7=D8=B1=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D8=A7=
=D9=84=D9=8A=D8=A9</span></b><span dir=3D"LTR"></span><span dir=3D"LTR"></s=
pan><b><span dir=3D"LTR" style=3D"font-size:22pt"><span dir=3D"LTR"></span>=
<span dir=3D"LTR"></span>
  IFRS</span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D9=85=D8=A7=D9=84=D9=8A=D8=B2=D9=8A=D8=A7</span></b=
><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span dir=3D"LTR" style=3D"font-size:22pt">1
  =E2=80=93 5 </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;fo=
nt-family:&quot;Times New Roman&quot;,serif">=D8=AF=D9=8A=D8=B3=D9=85=D8=A8=
=D8=B1</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b><=
/p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font=
-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:=
-0.5pt"><span dir=3D"RTL"></span><span dir=3D"RTL"></span><b><span lang=3D"=
AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New Roman&quot;,seri=
f"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>2000</span></b><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span><b><span lang=3D"AR-SA" dir=3D"L=
TR" style=3D"font-size:22pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></s=
pan> </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family=
:&quot;Times New Roman&quot;,serif">=D8=AF=D9=88=D9=84=D8=A7=D8=B1</span></=
b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9
  =D8=A7=D9=84=D9=85=D8=AE=D8=A7=D8=B7=D8=B1 =D8=A7=D9=84=D9=85=D8=A7=D9=84=
=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=AA=D8=AE=D8=B7=D9=8A=D8=B7 =D8=A7=D9=84=
=D9=85=D8=A7=D9=84=D9=8A</span></b><b><span dir=3D"LTR" style=3D"font-size:=
22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=AF=D8=A8=D9=8A</span></b><b><span dir=3D"LTR" st=
yle=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span dir=3D"LTR" style=3D"font-size:22pt">8
  =E2=80=93 12 </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;f=
ont-family:&quot;Times New Roman&quot;,serif">=D8=AF=D9=8A=D8=B3=D9=85=D8=
=A8=D8=B1</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></=
b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font=
-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:=
-0.5pt"><span dir=3D"RTL"></span><span dir=3D"RTL"></span><b><span lang=3D"=
AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New Roman&quot;,seri=
f"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>1750</span></b><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span><b><span lang=3D"AR-SA" dir=3D"L=
TR" style=3D"font-size:22pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></s=
pan> </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family=
:&quot;Times New Roman&quot;,serif">=D8=AF=D9=88=D9=84=D8=A7=D8=B1</span></=
b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=86=D9=
=82=D8=AF
  =D9=88=D8=A7=D9=84=D8=AA=D8=AF=D9=81=D9=82=D8=A7=D8=AA =D8=A7=D9=84=D9=85=
=D8=A7=D9=84=D9=8A=D8=A9</span></b><b><span dir=3D"LTR" style=3D"font-size:=
22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A5=D8=B3=D8=B7=D9=86=D8=A8=D9=88=D9=84</span></b=
><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span dir=3D"LTR" style=3D"font-size:22pt">8
  =E2=80=93 12 </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;f=
ont-family:&quot;Times New Roman&quot;,serif">=D8=AF=D9=8A=D8=B3=D9=85=D8=
=A8=D8=B1</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></=
b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font=
-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:=
-0.5pt"><b><span dir=3D"LTR" style=3D"font-size:22pt">1,400
  </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&q=
uot;Times New Roman&quot;,serif">=D8=AF=D9=88=D9=84=D8=A7=D8=B1</span></b><=
b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A7=D9=84=D9=85=D8=AD=D8=A7=D8=B3=D8=A8=D8=A9
  =D9=88=D8=A7=D9=84=D8=AA=D8=AD=D9=84=D9=8A=D9=84 =D8=A7=D9=84=D9=85=D8=A7=
=D9=84=D9=8A =D9=84=D8=BA=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D8=AD=D8=A7=D8=B3=
=D8=A8=D9=8A=D9=86</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt">=
</span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=AF=D8=A8=D9=8A</span></b><b><span dir=3D"LTR" st=
yle=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span dir=3D"LTR" style=3D"font-size:22pt">15
  =E2=80=93 19 </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;f=
ont-family:&quot;Times New Roman&quot;,serif">=D8=AF=D9=8A=D8=B3=D9=85=D8=
=A8=D8=B1</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></=
b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font=
-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:=
-0.5pt"><span dir=3D"RTL"></span><span dir=3D"RTL"></span><b><span lang=3D"=
AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New Roman&quot;,seri=
f"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>1750</span></b><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span><b><span lang=3D"AR-SA" dir=3D"L=
TR" style=3D"font-size:22pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></s=
pan> </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family=
:&quot;Times New Roman&quot;,serif">=D8=AF=D9=88=D9=84=D8=A7=D8=B1</span></=
b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A5=D8=B9=D8=AF=D8=A7=D8=AF
  =D8=A7=D9=84=D9=85=D9=8A=D8=B2=D8=A7=D9=86=D9=8A=D8=A7=D8=AA =D9=88=D8=A8=
=D8=B1=D8=A7=D9=85=D8=AC =D8=A7=D9=84=D8=B1=D9=82=D8=A7=D8=A8=D8=A9 =D8=A7=
=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9</span></b><b><span dir=3D"LTR" style=
=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=AF=D8=A8=D9=8A</span></b><b><span dir=3D"LTR" st=
yle=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span dir=3D"LTR" style=3D"font-size:22pt">22
  =E2=80=93 26 </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;f=
ont-family:&quot;Times New Roman&quot;,serif">=D8=AF=D9=8A=D8=B3=D9=85=D8=
=A8=D8=B1</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></=
b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font=
-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:=
-0.5pt"><span dir=3D"RTL"></span><span dir=3D"RTL"></span><b><span lang=3D"=
AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New Roman&quot;,seri=
f"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>1750</span></b><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span><b><span lang=3D"AR-SA" dir=3D"L=
TR" style=3D"font-size:22pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></s=
pan> </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family=
:&quot;Times New Roman&quot;,serif">=D8=AF=D9=88=D9=84=D8=A7=D8=B1</span></=
b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D9=85=D8=AD=D8=A7=D8=B3=D8=A8=D8=A9
  =D8=A7=D9=84=D8=AA=D9=83=D8=A7=D9=84=D9=8A=D9=81 =D8=A7=D9=84=D9=85=D8=AA=
=D9=82=D8=AF=D9=85=D8=A9 =D9=88=D8=A7=D8=AA=D8=AE=D8=A7=D8=B0 =D8=A7=D9=84=
=D9=82=D8=B1=D8=A7=D8=B1</span></b><b><span dir=3D"LTR" style=3D"font-size:=
22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A5=D8=B3=D8=B7=D9=86=D8=A8=D9=88=D9=84</span></b=
><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span dir=3D"LTR" style=3D"font-size:22pt">22
  =E2=80=93 26 </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;f=
ont-family:&quot;Times New Roman&quot;,serif">=D8=AF=D9=8A=D8=B3=D9=85=D8=
=A8=D8=B1</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></=
b></p>
  </td>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font=
-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:=
-0.5pt"><b><span dir=3D"LTR" style=3D"font-size:22pt">1,400
  </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&q=
uot;Times New Roman&quot;,serif">=D8=AF=D9=88=D9=84=D8=A7=D8=B1</span></b><=
b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>
  </td>
 </tr>
</tbody></table>

<div class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size=
:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5p=
t"><b><span dir=3D"LTR" style=3D"font-size:22pt">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></b></div>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28=
pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">=
<b><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Segoe UI Emo=
ji&quot;,sans-serif">=F0=9F=8E=AF</span></b><b><span dir=3D"LTR" style=3D"f=
ont-size:22pt"> </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;=
font-family:&quot;Times New Roman&quot;,serif">=D9=85=D9=85=D9=8A=D8=B2=D8=
=A7=D8=AA =D8=A7=D9=84=D8=AF=D9=88=D8=B1=D8=A7=D8=AA</span></b><span dir=3D=
"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-si=
ze:22pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>:</span></b></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"margin:0in 0.5in 0in 0in;text-align:center;direction:rtl;unicode-bidi:embe=
d;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-sp=
acing:-0.5pt"><b><span style=3D"font-size:10pt;font-family:Symbol">=C2=B7<s=
pan style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;fon=
t-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-fe=
ature-settings:normal;font-weight:normal;font-stretch:normal;font-size:7pt;=
line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0
</span></span></b><span dir=3D"RTL"></span><b><span lang=3D"AR-SA" style=3D=
"font-size:22pt;font-family:&quot;Times New Roman&quot;,serif">=D8=AA=D9=86=
=D9=81=D9=8A=D8=B0 =D8=AD=D8=B6=D9=88=D8=B1=D9=8A =D8=A3=D9=88
=D8=B9=D8=A8=D8=B1</span></b><span dir=3D"LTR"></span><span dir=3D"LTR"></s=
pan><b><span dir=3D"LTR" style=3D"font-size:22pt"><span dir=3D"LTR"></span>=
<span dir=3D"LTR"></span> Zoom</span></b></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"margin:0in 0.5in 0in 0in;text-align:center;direction:rtl;unicode-bidi:embe=
d;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-sp=
acing:-0.5pt"><b><span style=3D"font-size:10pt;font-family:Symbol">=C2=B7<s=
pan style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;fon=
t-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-fe=
ature-settings:normal;font-weight:normal;font-stretch:normal;font-size:7pt;=
line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0
</span></span></b><span dir=3D"RTL"></span><b><span lang=3D"AR-SA" style=3D=
"font-size:22pt;font-family:&quot;Times New Roman&quot;,serif">=D8=AA=D8=AF=
=D8=B1=D9=8A=D8=A8 =D8=B9=D9=85=D9=84=D9=8A
=D9=88=D9=85=D9=87=D9=86=D9=8A</span></b><b><span dir=3D"LTR" style=3D"font=
-size:22pt"></span></b></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"margin:0in 0.5in 0in 0in;text-align:center;direction:rtl;unicode-bidi:embe=
d;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-sp=
acing:-0.5pt"><b><span style=3D"font-size:10pt;font-family:Symbol">=C2=B7<s=
pan style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;fon=
t-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-fe=
ature-settings:normal;font-weight:normal;font-stretch:normal;font-size:7pt;=
line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0
</span></span></b><span dir=3D"RTL"></span><b><span lang=3D"AR-SA" style=3D=
"font-size:22pt;font-family:&quot;Times New Roman&quot;,serif">=D8=AE=D8=B5=
=D9=88=D9=85=D8=A7=D8=AA =D8=AE=D8=A7=D8=B5=D8=A9
=D9=84=D9=84=D9=85=D8=AC=D9=85=D9=88=D8=B9=D8=A7=D8=AA =D9=88=D8=A7=D9=84=
=D8=AC=D9=87=D8=A7=D8=AA =D8=A7=D9=84=D8=AD=D9=83=D9=88=D9=85=D9=8A=D8=A9</=
span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></span></b></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28=
pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">=
<b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New=
 Roman&quot;,serif">=C2=A0</span></b></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28=
pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">=
<a name=3D"_Hlk198725659"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;f=
ont-family:&quot;Times New Roman&quot;,serif">=D9=88=D8=A8=D9=87=D8=B0=D9=
=87 =D8=A7=D9=84=D9=85=D9=86=D8=A7=D8=B3=D8=A8=D8=A9
=D9=8A=D8=B3=D8=B9=D8=AF=D9=86=D8=A7 =D8=AF=D8=B9=D9=88=D8=AA=D9=83=D9=85 =
=D9=84=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83=D8=A9 =D9=88=D8=AA=D8=B9=D9=85=
=D9=8A=D9=85 =D8=AE=D8=B7=D8=A7=D8=A8=D9=86=D8=A7 =D8=B9=D9=84=D9=89 =D8=A7=
=D9=84=D9=85=D9=87=D8=AA=D9=85=D9=8A=D9=86 =D8=A8=D9=85=D9=80=D9=80=D9=88=
=D8=B6=D9=80=D9=88=D8=B9=C2=A0</span></b></a><b><span lang=3D"AR-EG" style=
=3D"font-size:22pt;font-family:&quot;Times New Roman&quot;,serif">=D8=A7=D9=
=84=D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =D8=A7=D9=84=D8=A7=D8=AD=D8=AA=D8=B1=D8=
=A7=D9=81=D9=8A=D8=A9=C2=A0</span></b><b><span lang=3D"AR-SA" style=3D"font=
-size:22pt;font-family:&quot;Times New Roman&quot;,serif">=D9=88=D8=A5=D9=
=81=D8=A7=D8=AF=D8=AA=D9=86=D8=A7 =D8=A8=D9=85=D9=86 =D8=AA=D9=82=D8=AA=D8=
=B1=D8=AD=D9=88=D9=86 =D8=AA=D9=88=D8=AC=D9=8A=D9=87 =D8=A7=D9=84=D8=AF=D8=
=B9=D9=88=D8=A9 =D9=84=D9=87=D9=85</span></b></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28=
pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">=
<b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New=
 Roman&quot;,serif">=D9=84=D9=85=D8=B2=D9=8A=D8=AF =D9=85=D9=86 =D8=A7=D9=
=84=D9=85=D8=B9=D9=84=D9=88=D9=85=D8=A7=D8=AA =D9=8A=D9=85=D9=83=D9=86=D9=
=83 =D8=A7=D9=84=D8=AA=D9=88=D8=A7=D8=B5=D9=84 =D9=85=D8=B9 =D8=A3 / =D8=B3=
=D8=A7=D8=B1=D8=A9
=D8=B9=D8=A8=D8=AF =D8=A7=D9=84=D8=AC=D9=88=D8=A7=D8=AF =E2=80=93 =D9=86=D8=
=A7=D8=A6=D8=A8 =D9=85=D8=AF=D9=8A=D8=B1 =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=
=8A=D8=A8 =E2=80=93 =D8=A7=D9=84=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=
=D8=A8=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=
=D8=A7=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9</span></b></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28=
pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">=
<b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New=
 Roman&quot;,serif">=D8=AC=D9=88=D8=A7=D9=84 =E2=80=93 =D9=88=D8=A7=D8=AA=
=D8=B3 =D8=A7=D8=A8 :</span></b><b><span dir=3D"LTR" style=3D"font-size:22p=
t"></span></b></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28=
pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">=
<b><span dir=3D"LTR" style=3D"font-size:22pt">00201069994399 -0020106299251=
0 -
00201096841626</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt"></sp=
an></b></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28=
pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">=
<b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New=
 Roman&quot;,serif">=C2=A0</span></b></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28=
pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">=
<span dir=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" styl=
e=3D"font-family:&quot;Segoe UI Symbol&quot;,sans-serif"><span dir=3D"LTR">=
</span><span dir=3D"LTR"></span>=E2=9C=85</span></b><b><span dir=3D"LTR"> <=
/span></b><b><span lang=3D"AR-SA" style=3D"font-family:&quot;Times New Roma=
n&quot;,serif">=D9=85=D9=84=D8=A7=D8=AD=D8=B8=D8=A7=D8=AA =D8=B9=D8=A7=D9=
=85=D8=A9</span></b><span dir=3D"LTR"></span><span dir=3D"LTR"></span><b><s=
pan dir=3D"LTR"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>:</span><=
/b></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28=
pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">=
<b><span lang=3D"AR-SA" style=3D"font-family:&quot;Times New Roman&quot;,se=
rif">=D8=AC=D9=85=D9=8A=D8=B9 =D8=A7=D9=84=D8=B4=D9=87=D8=A7=D8=AF=D8=A7=D8=
=AA =D8=AA=D8=B4=D9=85=D9=84 =D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =D9=85=D8=B9=D8=
=AA=D9=85=D8=AF=D8=A9=D8=8C =D8=AD=D9=82=D9=8A=D8=A8=D8=A9 =D8=AA=D8=AF=D8=
=B1=D9=8A=D8=A8=D9=8A=D8=A9=D8=8C
=D9=88=D9=88=D8=B1=D8=B4 =D8=B9=D9=85=D9=84 =D8=AA=D9=81=D8=A7=D8=B9=D9=84=
=D9=8A=D8=A9</span></b><span dir=3D"LTR"></span><span dir=3D"LTR"></span><b=
><span dir=3D"LTR"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</spa=
n></b><span dir=3D"LTR"></span></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28=
pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">=
<span lang=3D"AR-SA" style=3D"font-family:&quot;Times New Roman&quot;,serif=
">=D9=8A=D9=85=D9=83=D9=86 =D8=AA=D9=86=D9=81=D9=8A=D8=B0 =D8=A7=D9=84=D8=
=A8=D8=B1=D8=A7=D9=85=D8=AC <b>=D8=AD=D8=B6=D9=88=D8=B1=D9=8A=D9=8B=D8=A7 =
=D8=A3=D9=88 =D8=A3=D9=88=D9=86=D9=84=D8=A7=D9=8A=D9=86 =D8=B9=D8=A8=D8=B1<=
/b></span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D=
"LTR"><span dir=3D"LTR"></span><span dir=3D"LTR"></span> Zoom</span></b><sp=
an dir=3D"LTR">.</span></p>

<p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D"t=
ext-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font-s=
ize:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0=
.5pt"><span lang=3D"AR-SA" style=3D"font-family:&quot;Times New Roman&quot;=
,serif">=D8=A5=D9=85=D9=83=D8=A7=D9=86=D9=8A=D8=A9 =D8=AA=D8=AE=D8=B5=D9=8A=
=D8=B5 =D8=A3=D9=8A =D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =D9=84=D8=AA=D9=83=D9=88=
=D9=86 <b>=D8=AF=D8=A7=D8=AE=D9=84 =D8=A7=D9=84=D8=B4=D8=B1=D9=83=D8=A9</b>=
</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LT=
R"><span dir=3D"LTR"></span><span dir=3D"LTR"></span> (In-House)</span></b>=
<span dir=3D"LTR">.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;background-image:initial;background-position:initial;background-size:in=
itial;background-repeat:initial;background-origin:initial;background-clip:i=
nitial;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:106%=
;font-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" sty=
le=3D"font-size:16pt;font-family:Arial,sans-serif;color:red">=D9=84=D9=84=
=D8=AA=D8=B3=D8=AC=D9=8A=D9=84 =D9=88=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D9=81=
=D8=B3=D8=A7=D8=B1</span></b><span dir=3D"LTR" style=3D"font-size:16pt;colo=
r:red"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;background-image:initial;background-position:initial;background-size:in=
itial;background-repeat:initial;background-origin:initial;background-clip:i=
nitial;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:106%=
;font-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" sty=
le=3D"font-size:16pt;font-family:Arial,sans-serif">=D9=88=D8=A8=D9=87=D8=B0=
=D9=87 =D8=A7=D9=84=D9=85=D9=86=D8=A7=D8=B3=D8=A8=D8=A9 =D9=8A=D8=B3=D8=B9=
=D8=AF=D9=86=D8=A7 =D8=AF=D8=B9=D9=88=D8=AA=D9=83=D9=85 =D9=84=D9=84=D9=85=
=D8=B4=D8=A7=D8=B1=D9=83=D8=A9 =D9=88=D8=AA=D8=B9=D9=85=D9=8A=D9=85
=D8=AE=D8=B7=D8=A7=D8=A8=D9=86=D8=A7 =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D9=85=
=D9=87=D8=AA=D9=85=D9=8A=D9=86 =D8=A8=D9=85=D9=80=D9=80=D9=88=D8=B6=D9=80=
=D9=88=D8=B9=C2=A0</span></b><b><span lang=3D"AR-EG" style=3D"font-size:16p=
t;font-family:Arial,sans-serif">=D8=A7=D9=84=D8=B4=D9=87=D8=A7=D8=AF=D8=A9
=D8=A7=D9=84=D8=A7=D8=AD=D8=AA=D8=B1=D8=A7=D9=81=D9=8A=D8=A9=C2=A0</span></=
b><b><span lang=3D"AR-SA" style=3D"font-size:16pt;font-family:Arial,sans-se=
rif">=D9=88=D8=A5=D9=81=D8=A7=D8=AF=D8=AA=D9=86=D8=A7 =D8=A8=D9=85=D9=86 =
=D8=AA=D9=82=D8=AA=D8=B1=D8=AD=D9=88=D9=86 =D8=AA=D9=88=D8=AC=D9=8A=D9=87 =
=D8=A7=D9=84=D8=AF=D8=B9=D9=88=D8=A9 =D9=84=D9=87=D9=85</span></b><span dir=
=3D"LTR" style=3D"font-size:16pt"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;background-image:initial;background-position:initial;background-size:in=
itial;background-repeat:initial;background-origin:initial;background-clip:i=
nitial;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:106%=
;font-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" sty=
le=3D"font-size:16pt;font-family:Arial,sans-serif">=D9=84=D9=85=D8=B2=D9=8A=
=D8=AF =D9=85=D9=86 =D8=A7=D9=84=D9=85=D8=B9=D9=84=D9=88=D9=85=D8=A7=D8=AA =
=D9=8A=D9=85=D9=83=D9=86=D9=83 =D8=A7=D9=84=D8=AA=D9=88=D8=A7=D8=B5=D9=84 =
=D9=85=D8=B9 =D8=A3 / =D8=B3=D8=A7=D8=B1=D8=A9
=D8=B9=D8=A8=D8=AF =D8=A7=D9=84=D8=AC=D9=88=D8=A7=D8=AF =E2=80=93 =D9=86=D8=
=A7=D8=A6=D8=A8 =D9=85=D8=AF=D9=8A=D8=B1 =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=
=8A=D8=A8 =E2=80=93 =D8=A7=D9=84=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=
=D8=A8=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=
=D8=A7=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9</span></b><span lang=3D"AR-SA" style=
=3D"font-size:16pt"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;background-image:initial;background-position:initial;background-size:in=
itial;background-repeat:initial;background-origin:initial;background-clip:i=
nitial;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:106%=
;font-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" sty=
le=3D"font-size:16pt;font-family:Arial,sans-serif">=D8=AC=D9=88=D8=A7=D9=84=
 =E2=80=93 =D9=88=D8=A7=D8=AA=D8=B3 =D8=A7=D8=A8 :</span></b><span lang=3D"=
AR-SA" style=3D"font-size:16pt"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;background-image:initial;background-position:initial;background-size:in=
itial;background-repeat:initial;background-origin:initial;background-clip:i=
nitial;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:106%=
;font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR"></span><s=
pan dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:16pt"><span =
dir=3D"LTR"></span><span dir=3D"LTR"></span>00201069994399
-00201062992510 - 00201096841626</span></b><span lang=3D"AR-SA" style=3D"fo=
nt-size:16pt"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:106%;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"=
font-family:Arial,sans-serif">=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:106%;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR">=C2=A0</span=
></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:106%;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-EG" style=3D"=
font-family:Arial,sans-serif">=C2=A0</span></p></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CADj1ZK%3DRgHD3AOtRfk2qk%3D67onLVTpq%3Dd-v2H%3DKjeRj_c02T_w%40mai=
l.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.c=
om/d/msgid/kasan-dev/CADj1ZK%3DRgHD3AOtRfk2qk%3D67onLVTpq%3Dd-v2H%3DKjeRj_c=
02T_w%40mail.gmail.com</a>.<br />

--0000000000000f4930063bab37e4--
